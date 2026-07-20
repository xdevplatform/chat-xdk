// Package main — crypto core for the Go chat-xdk example bot.
//
// ChatCore is a thin, network-free wrapper around the chatxdk binding.
// Everything that touches the SDK lives here so it can be unit-tested directly
// (see chatcore_test.go). The four core feature touchpoints are all here:
//
//   - key management     -> LoadKeys / GenerateAndRegister / SetIdentity / SetSigningKeys
//   - conversation keys  -> PrepareConversationKeyChange / DecryptConversationKey
//     (plus the SDK's opt-in key cache, enabled in NewChatCore)
//   - message encryption -> EncryptReply
//   - event decryption   -> DecryptBatch (DecryptEvents) and DecryptOne (DecryptEvent)
package main

import (
	"encoding/base64"

	"github.com/xdevplatform/chat-xdk/go/chatxdk"
)

// ChatCore wraps a single unlocked chatxdk.Chat for one bot identity.
type ChatCore struct {
	chat              *chatxdk.Chat
	SigningKeyVersion string
}

// NewChatCore creates an empty (locked) core with the SDK's conversation-key
// cache enabled, so encrypt calls resolve the key from previously decrypted
// key-change events instead of the caller threading it through.
func NewChatCore() *ChatCore {
	chat := chatxdk.New()
	chat.SetCacheKeys(true)
	return &ChatCore{chat: chat, SigningKeyVersion: "1"}
}

// Close releases native resources.
func (c *ChatCore) Close() { c.chat.Close() }

// -- Key management ---------------------------------------------------------

// LoadKeys imports an existing base64 private-key blob (identity[+signing])
// registered under signingKeyVersion.
func (c *ChatCore) LoadKeys(privateKeysB64, signingKeyVersion string) error {
	keys, err := base64.StdEncoding.DecodeString(privateKeysB64)
	if err != nil {
		return err
	}
	if err := c.chat.ImportKeysWithVersion(keys, signingKeyVersion); err != nil {
		return err
	}
	c.SigningKeyVersion = signingKeyVersion
	return nil
}

// SetIdentity sets the session identity once the bot's user id is known;
// every encrypt/prepare call after this resolves its sender from the session
// instead of taking it as an argument.
func (c *ChatCore) SetIdentity(userID string) error {
	return c.chat.SetIdentity(userID, c.SigningKeyVersion)
}

// SetSigningKeys stores the senders' signing keys for decrypt calls that
// pass nil signing keys. Each call replaces the previous set.
func (c *ChatCore) SetSigningKeys(keys []chatxdk.SigningKeyEntry) error {
	return c.chat.SetSigningKeys(keys)
}

// GenerateAndRegister creates a fresh identity. Returns the registration
// payload to POST to the X API plus the exported private blob (base64 for
// persistence; the SDK returns raw bytes).
func (c *ChatCore) GenerateAndRegister() (payload *chatxdk.PublicKeyRegistrationPayload, privateKeysB64 string, err error) {
	payload, err = c.chat.GenerateKeypairs()
	if err != nil {
		return nil, "", err
	}
	privateKeys, err := c.chat.ExportKeys()
	if err != nil {
		return nil, "", err
	}
	return payload, base64.StdEncoding.EncodeToString(privateKeys), nil
}

// PublicKeys returns the loaded identity + signing public keys.
func (c *ChatCore) PublicKeys() (*chatxdk.PublicKeys, error) {
	return c.chat.GetPublicKeys()
}

// -- Conversation keys ------------------------------------------------------

// PrepareConversationKeyChange generates, encrypts, and signs a conversation-key
// change under the session identity. Leave conversationID empty for a
// one-to-one to derive it; pass it for a group.
func (c *ChatCore) PrepareConversationKeyChange(publicKeys []chatxdk.PublicKeyInput, conversationID string) (*chatxdk.PreparedConversationChange, error) {
	return c.chat.PrepareConversationKeyChange(chatxdk.ConversationKeyChangeParams{
		PublicKeys:     publicKeys,
		ConversationID: conversationID,
	})
}

// DecryptConversationKey ECIES-decrypts one conversation key (base64 in, raw bytes out).
func (c *ChatCore) DecryptConversationKey(encryptedKeyB64 string) ([]byte, error) {
	return c.chat.DecryptConversationKey(encryptedKeyB64)
}

// -- Decryption: the two paths ---------------------------------------------

// DecryptBatch is the batch path used on initial conversation load. It
// extracts conversation keys from KeyChange events (caching them for the
// encrypt calls), and decrypts every message. Passing nil signingKeys uses
// the set stored via SetSigningKeys.
func (c *ChatCore) DecryptBatch(eventsB64 []string, signingKeys []chatxdk.SigningKeyEntry) (*chatxdk.DecryptEventsResult, error) {
	return c.chat.DecryptEvents(eventsB64, signingKeys)
}

// DecryptOne is the single-event path used for each new event after the
// initial load. Passing nil maps resolves conversation keys from the SDK's
// key cache and signing keys from the set stored via SetSigningKeys;
// explicit maps override both.
func (c *ChatCore) DecryptOne(eventB64 string, conversationKeys map[string][]byte, signingKeys []chatxdk.SigningKeyEntry) (*chatxdk.Event, error) {
	return c.chat.DecryptEvent(eventB64, conversationKeys, signingKeys)
}

// -- Message encryption -----------------------------------------------------

// SendBody holds the fields the X API expects for an encrypted message.
type SendBody struct {
	MessageID                    string `json:"message_id"`
	EncodedMessageCreateEvent    string `json:"encoded_message_create_event"`
	EncodedMessageEventSignature string `json:"encoded_message_event_signature"`
	ConversationToken            string `json:"conversation_token,omitempty"`
}

// ReplyOptions are the optional send parameters for EncryptReply.
type ReplyOptions struct {
	// ReplyToEvent is the raw base64 event being replied to; when set the
	// message becomes a threaded reply and the SDK derives (and embeds) the
	// reply preview from the raw event.
	ReplyToEvent string
	// ReplyToCkces are raw base64 key-change events needed to decrypt the
	// original when it used a different key version than this reply.
	ReplyToCkces []string
	// Entities are (start, end, type) byte ranges within the text.
	Entities []chatxdk.EntityTuple
	// Attachments are attachment descriptors (e.g. a media reference).
	Attachments []chatxdk.AttachmentDescriptor
	// TTLMsec makes the message disappear after the given lifetime (0 = none).
	TTLMsec int64
	// ConversationKey/ConversationKeyVersion override the SDK's cached key —
	// needed only when the key never arrived in a decrypted event (e.g. a
	// just-created group).
	ConversationKey        []byte
	ConversationKeyVersion string
}

// EncryptReply encrypts + signs a message under the session identity and
// returns the send body. The conversation key resolves from the SDK's key
// cache unless opts overrides it. Without opts.ReplyToEvent (opts may be
// nil) it sends a fresh message via EncryptMessage; with it, the SDK's
// EncryptReply builds a *threaded* reply.
func (c *ChatCore) EncryptReply(conversationID, text string, opts *ReplyOptions) (*SendBody, error) {
	if opts == nil {
		opts = &ReplyOptions{}
	}
	var ttl *int64
	if opts.TTLMsec > 0 {
		ttl = &opts.TTLMsec
	}
	var payload *chatxdk.SendPayload
	var err error
	if opts.ReplyToEvent == "" {
		payload, err = c.chat.EncryptMessage(chatxdk.EncryptMessageParams{
			ConversationID:         conversationID,
			Text:                   text,
			ConversationKey:        opts.ConversationKey,
			ConversationKeyVersion: opts.ConversationKeyVersion,
			Entities:               opts.Entities,
			Attachments:            opts.Attachments,
			TTLMsec:                ttl,
		})
	} else {
		payload, err = c.chat.EncryptReply(chatxdk.EncryptReplyParams{
			ConversationID:         conversationID,
			Text:                   text,
			ReplyToEvent:           opts.ReplyToEvent,
			ReplyToCkces:           opts.ReplyToCkces,
			ConversationKey:        opts.ConversationKey,
			ConversationKeyVersion: opts.ConversationKeyVersion,
			Entities:               opts.Entities,
			Attachments:            opts.Attachments,
			TTLMsec:                ttl,
		})
	}
	if err != nil {
		return nil, err
	}
	return &SendBody{
		// The SDK generates the message id and returns it in the payload.
		MessageID:                    payload.MessageID,
		EncodedMessageCreateEvent:    payload.EncryptedContent,
		EncodedMessageEventSignature: payload.EncodedEventSignature,
	}, nil
}

// EncryptAddReaction encrypts + signs a reaction add targeting a raw event.
// conversationKey may be nil to use the SDK's cached key.
func (c *ChatCore) EncryptAddReaction(targetEventB64, emoji string, conversationKey []byte, conversationKeyVersion string) (*SendBody, error) {
	return c.encryptReaction(true, targetEventB64, emoji, conversationKey, conversationKeyVersion)
}

// EncryptRemoveReaction encrypts + signs a reaction remove targeting a raw
// event. conversationKey may be nil to use the SDK's cached key.
func (c *ChatCore) EncryptRemoveReaction(targetEventB64, emoji string, conversationKey []byte, conversationKeyVersion string) (*SendBody, error) {
	return c.encryptReaction(false, targetEventB64, emoji, conversationKey, conversationKeyVersion)
}

func (c *ChatCore) encryptReaction(add bool, targetEventB64, emoji string, conversationKey []byte, conversationKeyVersion string) (*SendBody, error) {
	// The conversation id and target sequence id derive from the raw event.
	params := chatxdk.EncryptReactionParams{
		TargetEvent:            targetEventB64,
		Emoji:                  emoji,
		ConversationKey:        conversationKey,
		ConversationKeyVersion: conversationKeyVersion,
	}
	encrypt := c.chat.EncryptAddReaction
	if !add {
		encrypt = c.chat.EncryptRemoveReaction
	}
	payload, err := encrypt(params)
	if err != nil {
		return nil, err
	}
	return &SendBody{
		// The SDK generates the message id and returns it in the payload.
		MessageID:                    payload.MessageID,
		EncodedMessageCreateEvent:    payload.EncryptedContent,
		EncodedMessageEventSignature: payload.EncodedEventSignature,
	}, nil
}

// -- Group management ---------------------------------------------------------

// PrepareGroupCreate prepares a group creation under the session identity:
// fresh key + the two required signatures.
func (c *ChatCore) PrepareGroupCreate(publicKeys []chatxdk.PublicKeyInput, conversationID string, memberIDs, adminIDs []string) (*chatxdk.PreparedConversationChange, error) {
	return c.chat.PrepareGroupCreate(chatxdk.GroupCreateParams{
		PublicKeys:     publicKeys,
		ConversationID: conversationID,
		MemberIDs:      memberIDs,
		AdminIDs:       adminIDs,
	})
}

// PrepareGroupMembersChange prepares a member add under the session
// identity: rotated key + the two required signatures.
func (c *ChatCore) PrepareGroupMembersChange(publicKeys []chatxdk.PublicKeyInput, conversationID string, newMemberIDs, currentMemberIDs, currentAdminIDs []string) (*chatxdk.PreparedConversationChange, error) {
	return c.chat.PrepareGroupMembersChange(chatxdk.GroupMembersChangeParams{
		PublicKeys:              publicKeys,
		ConversationID:          conversationID,
		NewMemberIDs:            newMemberIDs,
		CurrentMemberIDs:        currentMemberIDs,
		CurrentAdminIDs:         currentAdminIDs,
		CurrentPendingMemberIDs: []string{},
	})
}

// -- Media streaming ----------------------------------------------------------

// mediaChunk is the fixed chunk size fed through the incremental stream API.
const mediaChunk = 1024 * 1024

// EncryptMedia encrypts a media blob with the incremental stream API.
//
// Feeding fixed-size chunks through Push keeps memory bounded no matter how
// large the file is; Finish emits the final frame that seals the stream
// (decryption fails without it).
func (c *ChatCore) EncryptMedia(plaintext, conversationKey []byte) ([]byte, error) {
	enc, err := c.chat.StreamEncryptor(conversationKey)
	if err != nil {
		return nil, err
	}
	defer enc.Close()
	var out []byte
	for offset := 0; offset < len(plaintext); offset += mediaChunk {
		end := min(offset+mediaChunk, len(plaintext))
		part, err := enc.Push(plaintext[offset:end])
		if err != nil {
			return nil, err
		}
		out = append(out, part...)
	}
	final, err := enc.Finish()
	if err != nil {
		return nil, err
	}
	return append(out, final...), nil
}

// DecryptMedia decrypts a media blob with the incremental stream API.
//
// Finish errors if the stream was truncated, so plaintext from Push must not
// be treated as complete until it succeeds.
func (c *ChatCore) DecryptMedia(ciphertext, conversationKey []byte) ([]byte, error) {
	dec, err := c.chat.StreamDecryptor(conversationKey)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	var out []byte
	for offset := 0; offset < len(ciphertext); offset += mediaChunk {
		end := min(offset+mediaChunk, len(ciphertext))
		part, err := dec.Push(ciphertext[offset:end])
		if err != nil {
			return nil, err
		}
		out = append(out, part...)
	}
	final, err := dec.Finish()
	if err != nil {
		return nil, err
	}
	return append(out, final...), nil
}

// -- Generic helpers (handy for metadata + tests) ---------------------------

// Encrypt encrypts a UTF-8 string with the raw 32-byte conversation key.
func (c *ChatCore) Encrypt(plaintext string, conversationKey []byte) (string, error) {
	return c.chat.Encrypt(plaintext, conversationKey)
}

// Decrypt decrypts base64 ciphertext to a UTF-8 string.
func (c *ChatCore) Decrypt(ciphertextB64 string, conversationKey []byte) (string, error) {
	return c.chat.Decrypt(ciphertextB64, conversationKey)
}

// MessageText returns the plain text of a decrypted Message event, or "".
func MessageText(event *chatxdk.Event) string {
	msg := event.AsMessage()
	if msg == nil {
		return ""
	}
	return msg.Text()
}

// PrepToRequest maps a prepared conversation change into the X API request shape.
//
// Works for 1:1 key changes (one signature) and group create / member add
// (two signatures). signingPublicKey is the sender's own signing key, which
// the API expects alongside each signature.
func PrepToRequest(prep *chatxdk.PreparedConversationChange, signingPublicKey string) map[string]any {
	participantKeys := make([]map[string]any, 0, len(prep.ParticipantKeys))
	for _, pk := range prep.ParticipantKeys {
		participantKeys = append(participantKeys, map[string]any{
			"user_id":                    pk.UserID,
			"encrypted_conversation_key": pk.EncryptedKey,
			"public_key_version":         pk.PublicKeyVersion,
		})
	}
	actionSignatures := make([]map[string]any, 0, len(prep.ActionSignatures))
	for _, sig := range prep.ActionSignatures {
		entry := map[string]any{
			"message_id":                   sig.MessageID,
			"encoded_message_event_detail": sig.EncodedMessageEventDetail,
			"message_event_signature": map[string]any{
				"signature":          sig.Signature,
				"signature_version":  sig.SignatureVersion,
				"public_key_version": sig.PublicKeyVersion,
				"signing_public_key": signingPublicKey,
			},
		}
		if sig.SignaturePayload != "" {
			entry["signature_payload"] = sig.SignaturePayload
		}
		actionSignatures = append(actionSignatures, entry)
	}
	return map[string]any{
		"conversation_key_version":      prep.ConversationKeyVersion,
		"conversation_participant_keys": participantKeys,
		"action_signatures":             actionSignatures,
	}
}
