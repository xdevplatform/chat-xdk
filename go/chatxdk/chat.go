// Package chatxdk provides Go bindings for the X Chat SDK.
//
// It wraps the Rust chat-xdk-core library via C FFI (cgo), providing
// encryption for X Direct Messages.
//
// Design highlights:
//   - Pre-decrypted conversation keys for efficiency (decrypt once, reuse for all operations)
//   - One-call prepare methods that generate, encrypt, and sign key changes
//   - Native entity/attachment types (not JSON strings)
//
// Quick Start:
//
//	chat := chatxdk.New()
//	defer chat.Close()
//
//	// Generate keys and register with Juicebox
//	payload, _ := chat.GenerateKeypairs()
//	// POST payload to X API...
//	chat.Setup([]byte("2580"), juiceboxConfigJSON)
//
//	// Later: unlock with PIN and set the session identity + stores once.
//	chat.Unlock([]byte("2580"), juiceboxConfigJSON)
//	chat.SetIdentity(myUserID, mySigningKeyVersion)
//	chat.SetCacheKeys(true)
//	chat.SetSigningKeys(senderSigningKeys)
//
//	// Decrypt events. The batch path self-extracts conversation keys from
//	// KeyChange events (and caches them while SetCacheKeys is on); with nil
//	// signing keys the stored set is used.
//	result, _ := chat.DecryptEvents(eventsB64, nil)
//	event, err := chat.DecryptEvent(eventB64, nil, nil) // nil maps = session stores
//
//	// Encrypt messages: the sender identity and conversation key resolve
//	// from the session; the SDK generates the message id — read it back
//	// from payload.MessageID.
//	payload, _ := chat.EncryptMessage(EncryptMessageParams{
//	    ConversationID: conversationID,
//	    Text:           "Hello!",
//	})
package chatxdk

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"runtime"
)

// Chat is the main X Chat encryption SDK interface.
//
// Create with New(), free with Close(). A Chat is NOT safe for unsynchronized
// concurrent use: mutating operations (Setup, Unlock, Delete, ChangePin,
// UpdateConfig, SetRejectUnverified, SetIdentity,
// SetCacheKeys, SetSigningKeys) must not race decrypt or any other call on
// the same instance. Callers must serialize access externally (e.g. with a
// sync.Mutex) or confine each instance to one goroutine.
type Chat struct {
	h handle
}

// New creates a new Chat SDK instance.
//
// The returned Chat must be freed with Close() when no longer needed.
func New() *Chat {
	h := ffiNew()
	if h == nil {
		return nil
	}
	c := &Chat{h: h}
	// GC backstop for instances never explicitly Closed. A receiver becomes
	// collectible as soon as its last use passes — even while one of its
	// methods is still executing native code — so every method that hands
	// c.h to cgo defers runtime.KeepAlive(c), keeping this finalizer from
	// freeing the handle mid-call.
	runtime.SetFinalizer(c, func(c *Chat) { c.Close() })
	return c
}

// Close frees the Chat SDK instance and its resources.
// After Close, the Chat must not be used. Safe to call multiple times.
func (c *Chat) Close() {
	defer runtime.KeepAlive(c)
	if c.h != nil {
		ffiFree(c.h)
		c.h = nil
		runtime.SetFinalizer(c, nil)
	}
}

// IsUnlocked returns true if both identity and signing keys are loaded.
func (c *Chat) IsUnlocked() bool {
	defer runtime.KeepAlive(c)
	return ffiIsUnlocked(c.h) == 1
}

// HasIdentityKey returns true if the identity key is loaded (sufficient for decryption).
func (c *Chat) HasIdentityKey() bool {
	defer runtime.KeepAlive(c)
	return ffiHasIdentityKey(c.h) == 1
}

// SetRejectUnverified enables or disables rejection of unverified events.
// When enabled — the default — DecryptEvent returns an error for any signed
// event whose signature cannot be verified (invalid, missing, or no matching
// signing key) instead of returning it with Verified=false.
func (c *Chat) SetRejectUnverified(reject bool) {
	defer runtime.KeepAlive(c)
	ffiSetRejectUnverified(c.h, reject)
}

// SetIdentity sets the session identity: the owner's user ID and signing-key
// version, used as defaults wherever a params struct leaves SenderID /
// SigningKeyVersion empty. A resolved default and an explicitly passed value
// produce byte-identical signed output for the same logical inputs.
func (c *Chat) SetIdentity(userID, signingKeyVersion string) error {
	defer runtime.KeepAlive(c)
	return ffiSetIdentity(c.h, userID, signingKeyVersion)
}

// SetCacheKeys enables or disables the conversation-key cache (off by
// default). While enabled, DecryptEvents caches, per conversation, the key
// whose key change carried a valid signature at the highest version seen,
// and the encrypt methods resolve an omitted
// ConversationKey/ConversationKeyVersion pair from it. Disabling clears the
// cache.
func (c *Chat) SetCacheKeys(enabled bool) {
	defer runtime.KeepAlive(c)
	ffiSetCacheKeys(c.h, enabled)
}

// SetSigningKeys stores signing keys to use when a decrypt call passes nil
// (or empty) signingKeys. Each call replaces the previous set; only this
// call populates the store — a key carried inside an event is never trusted
// for verification.
func (c *Chat) SetSigningKeys(keys []SigningKeyEntry) error {
	defer runtime.KeepAlive(c)
	if keys == nil {
		keys = []SigningKeyEntry{}
	}
	b, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	return ffiSetSigningKeys(c.h, string(b))
}

// Lock clears keys from memory.
func (c *Chat) Lock() {
	defer runtime.KeepAlive(c)
	ffiLock(c.h)
}

// GenerateKeypairs generates new identity + signing keypairs.
func (c *Chat) GenerateKeypairs() (*PublicKeyRegistrationPayload, error) {
	defer runtime.KeepAlive(c)
	data, err := ffiGenerateKeypairs(c.h)
	if err != nil {
		return nil, err
	}
	var payload PublicKeyRegistrationPayload
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

// GetPublicKeys returns the user's current public keys.
func (c *Chat) GetPublicKeys() (*PublicKeys, error) {
	defer runtime.KeepAlive(c)
	data, err := ffiGetPublicKeys(c.h)
	if err != nil {
		return nil, err
	}
	var keys PublicKeys
	if err := json.Unmarshal([]byte(data), &keys); err != nil {
		return nil, err
	}
	return &keys, nil
}

// GetPublicKeyFingerprint returns the fingerprint of the loaded identity public key.
// Returns a URL-safe base64 string (SHA-256 of the SPKI-encoded key)
// that users can compare out-of-band to verify key authenticity.
func (c *Chat) GetPublicKeyFingerprint() (string, error) {
	defer runtime.KeepAlive(c)
	return ffiGetPublicKeyFingerprint(c.h)
}

// ExportKeys exports raw private key bytes (32 or 64) for backup, or nil
// when no identity key is loaded. Unlike a string, the byte slice can be
// zeroed once persisted.
// Warning: Handle with care — these are your secret keys!
func (c *Chat) ExportKeys() ([]byte, error) {
	defer runtime.KeepAlive(c)
	keysB64, err := ffiExportKeys(c.h)
	if err != nil {
		return nil, err
	}
	if keysB64 == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(keysB64)
}

// ImportKeys imports private keys from a byte slice produced by ExportKeys:
// 32 bytes (identity only) or 64 bytes (identity + signing). Unlike a string,
// the byte slice can be zeroed by the caller once imported; the base64 copy
// built here for the FFI transport is wiped before returning.
func (c *Chat) ImportKeys(keys []byte) error {
	defer runtime.KeepAlive(c)
	// NUL-terminated base64 buffer handed to C by pointer (no extra C-side
	// copy), so wiping it here covers the whole transport copy.
	buf := make([]byte, base64.StdEncoding.EncodedLen(len(keys))+1)
	base64.StdEncoding.Encode(buf, keys)
	_, err := ffiImportKeys(c.h, buf)
	clear(buf)
	return err
}

// ImportKeysWithVersion imports private keys like ImportKeys and also records
// the public key version they were registered under, so participant-key
// filtering and the session signing-key version are set in one call. The raw
// bytes are handed to the native side directly (no transport copy), so the
// caller's slice remains the only copy to wipe.
func (c *Chat) ImportKeysWithVersion(keys []byte, version string) error {
	defer runtime.KeepAlive(c)
	_, err := ffiImportKeysWithVersion(c.h, keys, version)
	return err
}

// ExtractConversationKeys extracts conversation keys from KeyChange events.
func (c *Chat) ExtractConversationKeys(events []string) (*ConversationKeyBundle, error) {
	defer runtime.KeepAlive(c)
	eventsJSON, err := json.Marshal(events)
	if err != nil {
		return nil, err
	}
	data, err := ffiExtractConversationKeys(c.h, string(eventsJSON))
	if err != nil {
		return nil, err
	}
	var out ConversationKeyBundle
	if err := json.Unmarshal([]byte(data), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DecryptEvents batch-decrypts webhook events (initial load / pagination).
// It self-extracts conversation keys from KeyChange events and never returns
// a per-event failure as an error: those are collected in the result's
// Errors map, keyed by event index.
//
// A nil (or empty) signingKeys falls back to the keys stored via
// SetSigningKeys; with nothing stored either, signed events fail decryption
// under the default reject-unverified policy.
func (c *Chat) DecryptEvents(events []string, signingKeys []SigningKeyEntry) (*DecryptEventsResult, error) {
	defer runtime.KeepAlive(c)
	eventsJSON, err := json.Marshal(events)
	if err != nil {
		return nil, err
	}
	signingJSON := "[]"
	if signingKeys != nil {
		b, err := json.Marshal(signingKeys)
		if err != nil {
			return nil, err
		}
		signingJSON = string(b)
	}
	data, err := ffiDecryptEvents(c.h, string(eventsJSON), signingJSON)
	if err != nil {
		return nil, err
	}
	var out DecryptEventsResult
	if err := json.Unmarshal([]byte(data), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PrepareConversationKeyChange generates, encrypts, and signs a conversation-key
// change, returning everything needed to POST it to the X API.
//
// Use this to start a one-to-one or rotate an existing conversation's key
// (one-to-one or group). Creating a group or adding members requires a paired
// group signature as well — use PrepareGroupCreate or PrepareGroupMembersChange
// for those.
//
// Leave ConversationID empty for a one-to-one to derive the canonical id from the
// two participants; pass the existing id for a group key rotation.
func (c *Chat) PrepareConversationKeyChange(params ConversationKeyChangeParams) (*PreparedConversationChange, error) {
	defer runtime.KeepAlive(c)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := ffiPrepareConversationKeyChange(c.h, string(j))
	if err != nil {
		return nil, err
	}
	var out PreparedConversationChange
	if err := json.Unmarshal([]byte(data), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PrepareGroupMembersChange generates, encrypts, and signs a group member-add
// change for the updated roster, returning everything needed to POST it. Emits
// two action signatures: a conversation-key change and the member add.
//
// Use this when adding members to an existing group. Creating the group is
// PrepareGroupCreate; a key rotation without a roster change is
// PrepareConversationKeyChange.
//
// CurrentTitle and CurrentAvatarURL may be empty; leave CurrentTTLMsec and
// CurrentScreenCaptureBlockingEnabled nil when unset.
func (c *Chat) PrepareGroupMembersChange(params GroupMembersChangeParams) (*PreparedConversationChange, error) {
	defer runtime.KeepAlive(c)
	// Rosters are required fields; marshal nil slices as [] rather than null.
	params.NewMemberIDs = orEmpty(params.NewMemberIDs)
	params.CurrentMemberIDs = orEmpty(params.CurrentMemberIDs)
	params.CurrentAdminIDs = orEmpty(params.CurrentAdminIDs)
	params.CurrentPendingMemberIDs = orEmpty(params.CurrentPendingMemberIDs)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := ffiPrepareGroupMembersChange(c.h, string(j))
	if err != nil {
		return nil, err
	}
	var out PreparedConversationChange
	if err := json.Unmarshal([]byte(data), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PrepareGroupCreate generates, encrypts, and signs a group create for the new
// roster, returning everything needed to POST it. Emits two action signatures:
// a conversation-key change and the group create.
//
// Use this once, when creating a group (ConversationID is the g-prefixed id
// minted by the initialize endpoint). Later key rotations use
// PrepareConversationKeyChange; roster additions use PrepareGroupMembersChange.
//
// Title and AvatarURL may be empty; leave TTLMsec nil when unset.
func (c *Chat) PrepareGroupCreate(params GroupCreateParams) (*PreparedConversationChange, error) {
	defer runtime.KeepAlive(c)
	// Rosters are required fields; marshal nil slices as [] rather than null.
	params.MemberIDs = orEmpty(params.MemberIDs)
	params.AdminIDs = orEmpty(params.AdminIDs)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := ffiPrepareGroupCreate(c.h, string(j))
	if err != nil {
		return nil, err
	}
	var out PreparedConversationChange
	if err := json.Unmarshal([]byte(data), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DecryptEvent decrypts a single webhook event and errors on failure.
//
// conversationKeys is a map of version -> raw 32-byte conversation key,
// from ExtractConversationKeys or DecryptConversationKey. A nil (or empty)
// map falls back to the opt-in conversation-key cache (SetCacheKeys); pass
// nil for non-message events.
//
// signingKeys is a list of signing keys for the sender; the SDK picks the
// matching version. A nil (or empty) list falls back to the keys stored via
// SetSigningKeys. With nothing stored either, every signed event fails under
// the default reject-unverified policy; only after SetRejectUnverified(false)
// are such events returned with Verified=false.
func (c *Chat) DecryptEvent(eventB64 string, conversationKeys map[string][]byte, signingKeys []SigningKeyEntry) (*Event, error) {
	defer runtime.KeepAlive(c)
	var convKeysJSON, signingKeysJSON string

	if conversationKeys != nil {
		b, err := json.Marshal(conversationKeys)
		if err != nil {
			return nil, err
		}
		convKeysJSON = string(b)
	} else {
		convKeysJSON = "{}"
	}

	if signingKeys != nil {
		b, err := json.Marshal(signingKeys)
		if err != nil {
			return nil, err
		}
		signingKeysJSON = string(b)
	} else {
		signingKeysJSON = "[]"
	}

	data, err := ffiDecryptEvent(c.h, eventB64, convKeysJSON, signingKeysJSON)
	if err != nil {
		return nil, err
	}
	var event Event
	if err := json.Unmarshal([]byte(data), &event); err != nil {
		return nil, err
	}
	return &event, nil
}

// EncryptMessage encrypts a message for the X API.
func (c *Chat) EncryptMessage(params EncryptMessageParams) (*SendPayload, error) {
	defer runtime.KeepAlive(c)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := ffiEncryptMessage(c.h, string(j))
	if err != nil {
		return nil, err
	}
	var payload SendPayload
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

// EncryptReply encrypts a reply message for the X API.
func (c *Chat) EncryptReply(params EncryptReplyParams) (*SendPayload, error) {
	defer runtime.KeepAlive(c)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := ffiEncryptReply(c.h, string(j))
	if err != nil {
		return nil, err
	}
	var payload SendPayload
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

// EncryptAddReaction encrypts a reaction-add for the X API.
func (c *Chat) EncryptAddReaction(params EncryptReactionParams) (*SendPayload, error) {
	defer runtime.KeepAlive(c)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := ffiEncryptAddReaction(c.h, string(j))
	if err != nil {
		return nil, err
	}
	var payload SendPayload
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

// EncryptRemoveReaction encrypts a reaction-remove for the X API.
func (c *Chat) EncryptRemoveReaction(params EncryptReactionParams) (*SendPayload, error) {
	defer runtime.KeepAlive(c)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := ffiEncryptRemoveReaction(c.h, string(j))
	if err != nil {
		return nil, err
	}
	var payload SendPayload
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

// DecryptConversationKey decrypts an encrypted conversation key (ECIES).
// Call this once per key version, then pass the result to DecryptEvent.
// Returns the raw 32-byte conversation key. Unlike a string, the byte
// slice can be zeroed once no longer needed.
func (c *Chat) DecryptConversationKey(encryptedKeyB64 string) ([]byte, error) {
	defer runtime.KeepAlive(c)
	keyB64, err := ffiDecryptConversationKey(c.h, encryptedKeyB64)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(keyB64)
}

// Encrypt encrypts a UTF-8 plaintext string with the raw 32-byte conversation
// key (metadata fields).
// Returns base64-encoded ciphertext (same wire format as message content encryption).
func (c *Chat) Encrypt(plaintext string, conversationKey []byte) (string, error) {
	defer runtime.KeepAlive(c)
	return ffiEncrypt(c.h, plaintext, base64.StdEncoding.EncodeToString(conversationKey))
}

// Decrypt decrypts base64 ciphertext to a UTF-8 plaintext string (metadata fields)
// with the raw 32-byte conversation key.
func (c *Chat) Decrypt(ciphertextB64 string, conversationKey []byte) (string, error) {
	defer runtime.KeepAlive(c)
	return ffiDecrypt(c.h, ciphertextB64, base64.StdEncoding.EncodeToString(conversationKey))
}

// DecryptStream decrypts a streaming-encrypted payload (e.g., media) with the
// raw 32-byte conversation key. Raw bytes in, raw bytes out; the FFI
// transports base64 internally.
func (c *Chat) DecryptStream(encrypted, conversationKey []byte) ([]byte, error) {
	defer runtime.KeepAlive(c)
	outB64, err := ffiDecryptStream(c.h,
		base64.StdEncoding.EncodeToString(encrypted),
		base64.StdEncoding.EncodeToString(conversationKey))
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(outB64)
}

// EncryptStream encrypts a stream (e.g., media) with the raw 32-byte
// conversation key. Raw bytes in, raw bytes out; the FFI transports base64
// internally.
func (c *Chat) EncryptStream(plaintext, conversationKey []byte) ([]byte, error) {
	defer runtime.KeepAlive(c)
	outB64, err := ffiEncryptStream(c.h,
		base64.StdEncoding.EncodeToString(plaintext),
		base64.StdEncoding.EncodeToString(conversationKey))
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(outB64)
}

// StreamEncryptor is an incremental stream encryptor for large payloads.
//
// Feed plaintext chunks with Push; call Finish once to emit the final
// frame. Always call Close to release the handle.
type StreamEncryptor struct {
	h streamEncryptorHandle
}

// StreamEncryptor creates an incremental stream encryptor for the given
// raw 32-byte conversation key.
func (c *Chat) StreamEncryptor(conversationKey []byte) (*StreamEncryptor, error) {
	h := ffiStreamEncryptorNew(base64.StdEncoding.EncodeToString(conversationKey))
	if h == nil {
		return nil, errors.New("invalid conversation key (expected 32 bytes)")
	}
	e := &StreamEncryptor{h: h}
	// GC backstop for encryptors never explicitly Closed. A receiver becomes
	// collectible as soon as its last use passes — even while one of its
	// methods is still executing native code — so every method that hands
	// e.h to cgo defers runtime.KeepAlive(e), keeping this finalizer from
	// freeing the handle (live secretstream key state) mid-call.
	runtime.SetFinalizer(e, func(e *StreamEncryptor) { e.Close() })
	return e, nil
}

// Push encrypts a plaintext chunk, returning ciphertext available so far
// (may be empty for small inputs).
func (e *StreamEncryptor) Push(plaintext []byte) ([]byte, error) {
	defer runtime.KeepAlive(e)
	outB64, err := ffiStreamEncryptorPush(e.h, base64.StdEncoding.EncodeToString(plaintext))
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(outB64)
}

// Finish emits the final frame and consumes the encryptor. Call Close
// afterwards to release the handle.
func (e *StreamEncryptor) Finish() ([]byte, error) {
	defer runtime.KeepAlive(e)
	outB64, err := ffiStreamEncryptorFinish(e.h)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(outB64)
}

// Close releases the underlying handle. Safe to call more than once.
func (e *StreamEncryptor) Close() {
	defer runtime.KeepAlive(e)
	if e.h != nil {
		ffiStreamEncryptorFree(e.h)
		e.h = nil
		runtime.SetFinalizer(e, nil)
	}
}

// StreamDecryptor is an incremental stream decryptor for large payloads.
//
// Feed ciphertext chunks with Push; call Finish once at end of input.
// Finish errors if the stream ended before its final frame (truncation), so do
// not treat plaintext from Push as complete until Finish succeeds. Always call
// Close to release the handle.
type StreamDecryptor struct {
	h streamDecryptorHandle
}

// StreamDecryptor creates an incremental stream decryptor for the given
// raw 32-byte conversation key.
func (c *Chat) StreamDecryptor(conversationKey []byte) (*StreamDecryptor, error) {
	h := ffiStreamDecryptorNew(base64.StdEncoding.EncodeToString(conversationKey))
	if h == nil {
		return nil, errors.New("invalid conversation key (expected 32 bytes)")
	}
	d := &StreamDecryptor{h: h}
	// GC backstop for decryptors never explicitly Closed. A receiver becomes
	// collectible as soon as its last use passes — even while one of its
	// methods is still executing native code — so every method that hands
	// d.h to cgo defers runtime.KeepAlive(d), keeping this finalizer from
	// freeing the handle (live secretstream key state) mid-call.
	runtime.SetFinalizer(d, func(d *StreamDecryptor) { d.Close() })
	return d, nil
}

// Push decrypts a ciphertext chunk, returning plaintext available so far
// (may be empty until enough input has arrived).
func (d *StreamDecryptor) Push(ciphertext []byte) ([]byte, error) {
	defer runtime.KeepAlive(d)
	outB64, err := ffiStreamDecryptorPush(d.h, base64.StdEncoding.EncodeToString(ciphertext))
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(outB64)
}

// Finish decrypts the final frame and consumes the decryptor. Call Close
// afterwards to release the handle.
func (d *StreamDecryptor) Finish() ([]byte, error) {
	defer runtime.KeepAlive(d)
	outB64, err := ffiStreamDecryptorFinish(d.h)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(outB64)
}

// Close releases the underlying handle. Safe to call more than once.
func (d *StreamDecryptor) Close() {
	defer runtime.KeepAlive(d)
	if d.h != nil {
		ffiStreamDecryptorFree(d.h)
		d.h = nil
		runtime.SetFinalizer(d, nil)
	}
}

// Sign signs arbitrary data with the signing key.
// Returns the raw 64-byte ECDSA P-256 signature.
func (c *Chat) Sign(data []byte) ([]byte, error) {
	defer runtime.KeepAlive(c)
	sigB64, err := ffiSign(c.h, data)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(sigB64)
}

// Verify verifies a raw signature (from Sign) against a base64-encoded
// signing public key.
func (c *Chat) Verify(publicKeyB64 string, signature, data []byte) (bool, error) {
	defer runtime.KeepAlive(c)
	rc, err := ffiVerify(c.h, publicKeyB64, base64.StdEncoding.EncodeToString(signature), data)
	if err != nil {
		return false, err
	}
	switch rc {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		return false, errors.New("verification error")
	}
}

// VerifyKeyBinding verifies that a signing key is authentically bound to an
// identity key. Call this when you receive another user's public keys from
// the X API to detect server-side key substitution. All arguments are
// base64-encoded.
func (c *Chat) VerifyKeyBinding(identityPublicKeyB64, signingPublicKeyB64, identityPublicKeySignatureB64 string) (bool, error) {
	defer runtime.KeepAlive(c)
	switch ffiVerifyKeyBinding(c.h, identityPublicKeyB64, signingPublicKeyB64, identityPublicKeySignatureB64) {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		return false, errors.New("key binding verification error")
	}
}

// MatchesRegisteredKey reports whether the loaded identity public key is the
// key in publicKeyB64. The X API returns the identity public key in SPKI/DER
// encoding while GetPublicKeys returns the raw SEC1 point; this accepts
// either encoding, so use it to check whether the keys on this device belong
// to a key registered to the account.
func (c *Chat) MatchesRegisteredKey(publicKeyB64 string) (bool, error) {
	defer runtime.KeepAlive(c)
	switch ffiMatchesRegisteredKey(c.h, publicKeyB64) {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		return false, errors.New("registered key match error")
	}
}
