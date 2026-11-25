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
//	registration, _ := chat.GenerateKeypairs()
//	// POST registration to X API...
//	chat.Setup([]byte("2580"), juiceboxConfigJSON)
//
//	// Later: unlock with PIN and set the session identity + stores once.
//	chat.Unlock([]byte("2580"), juiceboxConfigJSON)
//	chat.SetIdentity(chatxdk.SetIdentityParams{UserID: myUserID, SigningKeyVersion: mySigningKeyVersion})
//	chat.SetCacheKeys(true)
//	chat.SetSigningKeys(senderSigningKeys)
//
//	// Or let the Chat ask for the public keys it lacks: the hook returns,
//	// by user id, the records GET /2/users/{id}/public_keys returns in
//	// data. Setting a hook turns the key cache on.
//	chat.SetResolvePublicKeys(func(userIDs []string) (map[string][]chatxdk.PublicKeyRecord, error) {
//	    return fetchPublicKeys(userIDs)
//	})
//
//	// Decrypt events. The batch path self-extracts conversation keys from
//	// KeyChange events; while SetCacheKeys is on, both decrypt calls cache
//	// the key of each key change that verifies. With nil signing keys the
//	// stored set is used.
//	result, _ := chat.DecryptEvents(chatxdk.DecryptEventsParams{Events: eventsB64})
//	event, err := chat.DecryptEvent(chatxdk.DecryptEventParams{
//	    EventB64:         eventB64,
//	    ConversationKeys: result.ConversationKeys.Keys,
//	})
//
//	// Encrypt messages: the sender identity and conversation key resolve
//	// from the session; the SDK generates the message id — read it back
//	// from payload.MessageID.
//	payload, _ := chat.EncryptMessage(chatxdk.EncryptMessageParams{
//	    ConversationID: conversationID,
//	    Text:           "Hello!",
//	})
package chatxdk

import (
	"encoding/base64"
	"encoding/json"
	"runtime"
	"sync"
)

// Chat is the main X Chat encryption SDK interface.
//
// Create with New() (or NewWithJuiceboxConfig() to keep the keys in
// Juicebox), free with Close(). Its methods may be called from several
// goroutines at once; Close must not race them.
type Chat struct {
	h handle

	// resolveMu guards resolvePublicKeys. It is held to read or replace the
	// hook, never while the hook runs.
	resolveMu sync.Mutex
	// resolvePublicKeys is the hook SetResolvePublicKeys set, or nil.
	resolvePublicKeys func(userIDs []string) (map[string][]PublicKeyRecord, error)
}

// New creates a new Chat SDK instance. It reads the X API's feature switches
// in the background, retries a read that fails, and reads them again five
// minutes after each answer, so a change reaches a running Chat.
//
// The returned Chat must be freed with Close() when no longer needed.
func New() *Chat {
	c, err := newChat(nil)
	if err != nil {
		return nil
	}
	c.startFeatures()
	return c
}

// newChat creates a Chat, with a Juicebox configuration unless
// juiceboxConfigJSON is empty, that has not started reading its feature
// switches.
// newChat creates a Chat with juiceboxConfigJSON, or with no Juicebox config
// when it is nil.
func newChat(juiceboxConfigJSON *string) (*Chat, error) {
	h, err := ffiNew(juiceboxConfigJSON)
	if err != nil {
		return nil, err
	}
	c := &Chat{h: h}
	// GC backstop for instances never explicitly Closed. A receiver becomes
	// collectible as soon as its last use passes — even while one of its
	// methods is still executing native code — so every method that hands
	// c.h to cgo defers runtime.KeepAlive(c), keeping this finalizer from
	// freeing the handle mid-call.
	runtime.SetFinalizer(c, func(c *Chat) { c.Close() })
	return c, nil
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
	unlocked, _ := ffiIsUnlocked(c.h)
	return unlocked
}

// HasIdentityKey returns true if the identity key is loaded (sufficient for decryption).
func (c *Chat) HasIdentityKey() bool {
	defer runtime.KeepAlive(c)
	loaded, _ := ffiHasIdentityKey(c.h)
	return loaded
}

// SetRejectUnverified enables or disables rejection of unverified events.
// When enabled — the default — DecryptEvent returns an error for any signed
// event whose signature cannot be verified (invalid, missing, or no matching
// signing key) instead of returning it with Verified=false.
func (c *Chat) SetRejectUnverified(reject bool) {
	defer runtime.KeepAlive(c)
	_ = ffiSetRejectUnverified(c.h, reject)
}

// SetIdentity sets the session identity: the owner's user ID and signing-key
// version, used as defaults wherever a params struct leaves SenderID /
// SigningKeyVersion empty. A resolved default and an explicitly passed value
// produce byte-identical signed output for the same logical inputs. The
// signing-key version is the public_key_version returned when the keys were
// registered. The Chat then reads its feature switches for this sender's
// bucket, the last four digits of the user ID.
func (c *Chat) SetIdentity(params SetIdentityParams) error {
	defer runtime.KeepAlive(c)
	j, err := json.Marshal(params)
	if err != nil {
		return err
	}
	if err := ffiSetIdentity(c.h, string(j)); err != nil {
		return err
	}
	c.startFeatures()
	return nil
}

// SetCacheKeys enables or disables the conversation-key cache (off by
// default).
//
// While enabled, the cache keeps, per conversation, the key of every key
// change whose signature verified in DecryptEvents or DecryptEvent, and the
// key of every key change this Chat prepared (PrepareConversationKeyChange,
// PrepareGroupCreate, PrepareGroupMembersChange or
// PrepareGroupMembersRemove). A call that omits its conversation key reads
// it from there: the encrypt methods and the title, description and avatar
// changes use the conversation's newest key, and DecryptEvent, DecryptFile
// and FileDecryptor the key at the version the event names. Disabling clears
// the cache.
//
// A prepared key is cached when the prepare call returns, before its request
// is sent. If the X API rejects the request, no one else holds that key:
// prepare the change again, or pass the key to encrypt with explicitly,
// until a newer key change verifies.
func (c *Chat) SetCacheKeys(enabled bool) {
	defer runtime.KeepAlive(c)
	_ = ffiSetCacheKeys(c.h, enabled)
}

// SetSigningKeys stores signing keys to use when a decrypt call's params leave
// SigningKeys nil (or empty). Each call replaces the previous set; add to it
// with AddSigningKeys or AddPublicKeys. Only these calls populate the store —
// a key carried inside an event is never trusted for verification.
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

// AddSigningKeys adds signing keys to the set SetSigningKeys stores, keeping
// the keys it holds: an entry replaces the stored entry of the same UserID
// and PublicKeyVersion, and any other is added.
func (c *Chat) AddSigningKeys(keys []SigningKeyEntry) error {
	defer runtime.KeepAlive(c)
	if keys == nil {
		keys = []SigningKeyEntry{}
	}
	b, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	return ffiAddSigningKeys(c.h, string(b))
}

// AddPublicKeys adds users' public keys to the stored signing keys, as
// AddSigningKeys adds entries. records holds, by user id, the records
// GET /2/users/{id}/public_keys returns in data for that user. A record
// without a key version, an identity key or a signing key is left out.
//
// The decrypt calls verify with the stored keys when their SigningKeys are
// nil, and PrepareConversationKeyChange, PrepareGroupCreate,
// PrepareGroupMembersChange and PrepareGroupMembersRemove encrypt the new
// conversation key to their members' stored keys when their PublicKeys are
// nil.
func (c *Chat) AddPublicKeys(records map[string][]PublicKeyRecord) error {
	defer runtime.KeepAlive(c)
	if len(records) == 0 {
		return nil
	}
	b, err := json.Marshal(records)
	if err != nil {
		return err
	}
	return ffiAddPublicKeys(c.h, string(b))
}

// MissingPublicKeys returns the users whose public keys a DecryptEvents
// result was missing: the sender of each event in its MissingSigningKeys,
// once each, in batch order. Fetch their keys
// (GET /2/users/{id}/public_keys), add them with AddPublicKeys, and decrypt
// the batch again.
//
// A key this call returned a user for is not asked for again for a minute,
// so a lookup that brought no key is not repeated with every batch. A key
// that arrives is no longer missing, and a key version not asked for before
// is asked for at once.
func (c *Chat) MissingPublicKeys(result *DecryptEventsResult) ([]string, error) {
	defer runtime.KeepAlive(c)
	if result == nil || len(result.MissingSigningKeys) == 0 {
		return []string{}, nil
	}
	b, err := json.Marshal(result.MissingSigningKeys)
	if err != nil {
		return nil, err
	}
	data, err := ffiMissingPublicKeys(c.h, string(b))
	if err != nil {
		return nil, err
	}
	return decodeUserIDs(data)
}

// The names the native side knows the prepare calls that encrypt a new
// conversation key by.
const (
	callConversationKeyChange = "conversation_key_change"
	callGroupCreate           = "group_create"
	callGroupMembersChange    = "group_members_change"
	callGroupMembersRemove    = "group_members_remove"
)

// missingPublicKeysFor returns the users whose public keys the prepare call
// named call would be missing with params: the members it encrypts its key
// to who have no stored public key, and none when params passes PublicKeys.
// A user it returned is not returned again for a minute while no key is
// stored for that user.
func (c *Chat) missingPublicKeysFor(call string, params any) ([]string, error) {
	defer runtime.KeepAlive(c)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := ffiMissingPublicKeysFor(c.h, call, string(j))
	if err != nil {
		return nil, err
	}
	return decodeUserIDs(data)
}

// decodeUserIDs reads the JSON array of user ids a native call returned.
func decodeUserIDs(data string) ([]string, error) {
	userIDs := []string{}
	if err := json.Unmarshal([]byte(data), &userIDs); err != nil {
		return nil, err
	}
	return userIDs, nil
}

// SetResolvePublicKeys sets the hook that fetches users' public keys, or
// removes it with nil. The hook is given user ids and returns, by user id,
// the records GET /2/users/{id}/public_keys returns in data for each; a user
// it has nothing for is left out.
//
// With a hook set:
//
//   - DecryptEvents, when its SigningKeys are nil, calls the hook for the
//     users its result reports in MissingSigningKeys, adds what it returns
//     (AddPublicKeys), and decrypts the batch once more.
//   - PrepareConversationKeyChange, PrepareGroupCreate,
//     PrepareGroupMembersChange and PrepareGroupMembersRemove, when their
//     PublicKeys are nil, call the hook for the members they have no stored
//     public key for and add what it returns before they encrypt the new
//     key.
//
// An error the hook returns is returned by the call that ran it. A user the
// hook was asked for and returned no key for is not asked for again for a
// minute, so a lookup that fails is not repeated with every call.
//
// Setting a hook turns the key cache on (SetCacheKeys); removing it leaves
// the cache as it is. The hook runs on the goroutine of the call that needs
// the keys, and may be called from several goroutines at once.
func (c *Chat) SetResolvePublicKeys(hook func(userIDs []string) (map[string][]PublicKeyRecord, error)) {
	c.resolveMu.Lock()
	c.resolvePublicKeys = hook
	c.resolveMu.Unlock()
	if hook != nil {
		c.SetCacheKeys(true)
	}
}

// publicKeysHook returns the hook SetResolvePublicKeys set, or nil.
func (c *Chat) publicKeysHook() func(userIDs []string) (map[string][]PublicKeyRecord, error) {
	c.resolveMu.Lock()
	defer c.resolveMu.Unlock()
	return c.resolvePublicKeys
}

// runPublicKeysHook calls hook for userIDs and stores the records it
// returns.
func (c *Chat) runPublicKeysHook(hook func(userIDs []string) (map[string][]PublicKeyRecord, error), userIDs []string) error {
	records, err := hook(userIDs)
	if err != nil {
		return err
	}
	return c.AddPublicKeys(records)
}

// resolvePublicKeysFor gets, through the hook when one is set, the public
// keys the prepare call named call lacks. params is that call's params; a
// call that passes PublicKeys needs none.
func (c *Chat) resolvePublicKeysFor(call string, params any, passesPublicKeys bool) error {
	hook := c.publicKeysHook()
	if hook == nil || passesPublicKeys {
		return nil
	}
	missing, err := c.missingPublicKeysFor(call, params)
	if err != nil {
		return err
	}
	if len(missing) == 0 {
		return nil
	}
	return c.runPublicKeysHook(hook, missing)
}

// Lock clears keys from memory.
func (c *Chat) Lock() {
	defer runtime.KeepAlive(c)
	_ = ffiLock(c.h)
}

// GenerateKeypairs generates new identity + signing keypairs.
//
// No signing-key version is set: after registering the keys, call
// SetIdentity with the public_key_version the registration returns.
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

// ExportKeys exports raw private key bytes (32 or 64) for backup. It fails
// with an *Error of kind ErrorKindInvalidState when no identity key is
// loaded. Unlike a string, the byte slice can be zeroed once persisted.
// Warning: Handle with care — these are your secret keys!
func (c *Chat) ExportKeys() ([]byte, error) {
	defer runtime.KeepAlive(c)
	keysB64, err := ffiExportKeys(c.h)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(keysB64)
}

// ImportKeys imports private keys from the byte slice ExportKeys produced:
// 32 bytes (identity only) or 64 bytes (identity + signing). When
// params.SigningKeyVersion is set, it also records the public_key_version
// returned when the keys were registered, so participant-key filtering and
// the session signing-key version are set in one call. The key bytes are
// handed to the native side directly, never copied into a string, so the
// caller's slice remains the only copy to wipe.
func (c *Chat) ImportKeys(params ImportKeysParams) error {
	defer runtime.KeepAlive(c)
	j, err := json.Marshal(params)
	if err != nil {
		return err
	}
	_, err = ffiImportKeys(c.h, params.Keys, string(j))
	return err
}

// ExtractConversationKeys extracts conversation keys from KeyChange events.
// Signatures are not checked. The bundle's LatestVersion is the batch's
// highest key version when every event belongs to one conversation, and nil
// when they belong to more than one: read LatestVersions by conversation id.
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
// Nil (or empty) SigningKeys fall back to the keys stored via
// SetSigningKeys, AddSigningKeys and AddPublicKeys; with nothing stored
// either, signed events fail decryption under the default reject-unverified
// policy. A member removal's title and description, re-encrypted under the
// new key, aren't changes: they land in Errors under either policy.
//
// The signing keys must include those of every member who signed a key
// change in the batch, whether or not that member sent a message in it.
// Under either policy, a recent key change whose signature does not verify
// has its key dropped, and every message under that key then lands in
// Errors. The result's MissingSigningKeys holds, for each signed event whose
// sender's signing key the call lacked, the user and key version to fetch:
// MissingPublicKeys lists those users, AddPublicKeys stores their keys, and
// the batch then decrypts. Its UnverifiedKeyChanges holds each key change
// whose signature did not verify with why, its UndecryptableKeyChanges each
// key change whose key this chat could not decrypt, and its
// RejectedSigningKeys each signing key left out because its identity binding
// does not verify.
//
// With a SetResolvePublicKeys hook set and nil SigningKeys, the call fetches
// the missing keys itself: it calls the hook for MissingPublicKeys of its
// result, stores what the hook returns, and decrypts the batch once more.
// The result then reports only what is still missing. An error from the hook
// is returned as the call's error.
//
// For a batch whose events belong to more than one conversation, read
// ConversationKeys.KeysByConversation and ConversationKeys.LatestVersions by
// conversation id: ConversationKeys.LatestVersion is nil for such a batch.
func (c *Chat) DecryptEvents(params DecryptEventsParams) (*DecryptEventsResult, error) {
	defer runtime.KeepAlive(c)
	params.Events = orEmpty(params.Events)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	result, err := c.decryptEvents(string(j))
	if err != nil {
		return nil, err
	}
	hook := c.publicKeysHook()
	if hook == nil || len(params.SigningKeys) > 0 {
		return result, nil
	}
	missing, err := c.MissingPublicKeys(result)
	if err != nil {
		return nil, err
	}
	if len(missing) == 0 {
		return result, nil
	}
	if err := c.runPublicKeysHook(hook, missing); err != nil {
		return nil, err
	}
	return c.decryptEvents(string(j))
}

// decryptEvents batch-decrypts the events of a DecryptEvents params
// document.
func (c *Chat) decryptEvents(paramsJSON string) (*DecryptEventsResult, error) {
	defer runtime.KeepAlive(c)
	data, err := ffiDecryptEvents(c.h, paramsJSON)
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
//
// With nil PublicKeys the key is encrypted to the stored public keys
// (AddPublicKeys) of the users in MemberIDs, or, without MemberIDs, of the
// two users of the one-to-one conversation ConversationID names. A
// SetResolvePublicKeys hook is called first for the users among them with no
// stored key. A user still without one fails the call with an
// ErrorKindInvalidInput error that names the user.
//
// While the key cache is on (SetCacheKeys), the new key is cached when the
// call returns.
func (c *Chat) PrepareConversationKeyChange(params ConversationKeyChangeParams) (*PreparedConversationChange, error) {
	defer runtime.KeepAlive(c)
	if err := c.resolvePublicKeysFor(callConversationKeyChange, params, len(params.PublicKeys) > 0); err != nil {
		return nil, err
	}
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := ffiPrepareConversationKeyChange(c.h, string(j))
	if err != nil {
		return nil, err
	}
	return decodePreparedConversationChange(data)
}

// PrepareGroupMembersChange generates, encrypts, and signs a group member-add
// change for the updated roster, returning everything needed to POST it. Emits
// two action signatures: a conversation-key change and the member add.
//
// Use this when adding members to an existing group. Creating the group is
// PrepareGroupCreate; a key rotation without a roster change is
// PrepareConversationKeyChange.
//
// CurrentTitle, CurrentDescription and CurrentAvatarURL may be empty; leave
// CurrentTTLMsec and CurrentScreenCaptureBlockingEnabled nil when unset.
// CurrentTitle and CurrentDescription are plaintext: the call encrypts each
// under the new conversation key, signs the ciphertext, and returns it as
// EncryptedTitle and EncryptedDescription. CurrentAvatarURL is the avatar's
// media URL, signed as is.
//
// With nil PublicKeys the key is encrypted to the stored public keys
// (AddPublicKeys) of the users in CurrentMemberIDs and NewMemberIDs. A
// SetResolvePublicKeys hook is called first for the users among them with no
// stored key. A user still without one fails the call with an
// ErrorKindInvalidInput error that names the user.
//
// While the key cache is on (SetCacheKeys), the new key is cached when the
// call returns.
func (c *Chat) PrepareGroupMembersChange(params GroupMembersChangeParams) (*PreparedConversationChange, error) {
	defer runtime.KeepAlive(c)
	// Rosters are required fields; marshal nil slices as [] rather than null.
	params.NewMemberIDs = orEmpty(params.NewMemberIDs)
	params.CurrentMemberIDs = orEmpty(params.CurrentMemberIDs)
	params.CurrentAdminIDs = orEmpty(params.CurrentAdminIDs)
	params.CurrentPendingMemberIDs = orEmpty(params.CurrentPendingMemberIDs)
	if err := c.resolvePublicKeysFor(callGroupMembersChange, params, len(params.PublicKeys) > 0); err != nil {
		return nil, err
	}
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := ffiPrepareGroupMembersChange(c.h, string(j))
	if err != nil {
		return nil, err
	}
	return decodePreparedConversationChange(data)
}

// PrepareGroupCreate generates, encrypts, and signs a group create for the new
// roster, returning everything needed to POST it. Emits two action signatures:
// a conversation-key change and the group create.
//
// Use this once, when creating a group (ConversationID is the g-prefixed id
// minted by the initialize endpoint). Later key rotations use
// PrepareConversationKeyChange; roster additions use PrepareGroupMembersChange.
//
// Title is plaintext and may be empty; leave TTLMsec nil when unset. The call
// encrypts a title under the new conversation key, signs the ciphertext, and
// returns it as EncryptedTitle: the group_name the create request sends. A
// create sets no avatar; set it afterwards with PrepareGroupAvatarChange.
//
// With nil PublicKeys the key is encrypted to the stored public keys
// (AddPublicKeys) of the users in MemberIDs and AdminIDs. A
// SetResolvePublicKeys hook is called first for the users among them with no
// stored key. A user still without one fails the call with an
// ErrorKindInvalidInput error that names the user.
//
// While the key cache is on (SetCacheKeys), the new key is cached when the
// call returns.
func (c *Chat) PrepareGroupCreate(params GroupCreateParams) (*PreparedConversationChange, error) {
	defer runtime.KeepAlive(c)
	// Rosters are required fields; marshal nil slices as [] rather than null.
	params.MemberIDs = orEmpty(params.MemberIDs)
	params.AdminIDs = orEmpty(params.AdminIDs)
	if err := c.resolvePublicKeysFor(callGroupCreate, params, len(params.PublicKeys) > 0); err != nil {
		return nil, err
	}
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := ffiPrepareGroupCreate(c.h, string(j))
	if err != nil {
		return nil, err
	}
	return decodePreparedConversationChange(data)
}

// PrepareGroupMembersRemove signs a group member removal and rotates the
// conversation key for the members who stay.
//
// PublicKeys are the identity keys of the members who stay. The result
// carries the new key, those members' participant keys, and the action
// signatures: the removal (which names the new key version), a title and a
// description change for each one the params set, re-encrypted under the new
// key, and the key change.
//
// With nil PublicKeys the key is encrypted to the stored public keys
// (AddPublicKeys) of the users in RemainingMemberIDs. A SetResolvePublicKeys
// hook is called first for the users among them with no stored key. A user
// still without one fails the call with an ErrorKindInvalidInput error that
// names the user.
//
// While the key cache is on (SetCacheKeys), the new key is cached when the
// call returns.
func (c *Chat) PrepareGroupMembersRemove(params GroupMembersRemoveParams) (*PreparedConversationChange, error) {
	defer runtime.KeepAlive(c)
	if params.PublicKeys == nil {
		params.PublicKeys = []PublicKeyInput{}
	}
	params.UserIDs = orEmpty(params.UserIDs)
	if err := c.resolvePublicKeysFor(callGroupMembersRemove, params, len(params.PublicKeys) > 0); err != nil {
		return nil, err
	}
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := ffiPrepareGroupMembersRemove(c.h, string(j))
	if err != nil {
		return nil, err
	}
	return decodePreparedConversationChange(data)
}

// preparedConversationChangeWire is a native prepare result, which carries the
// conversation key that PreparedConversationChange keeps out of its JSON.
type preparedConversationChangeWire struct {
	PreparedConversationChange
	ConversationKey []byte `json:"conversation_key"`
}

func decodePreparedConversationChange(data string) (*PreparedConversationChange, error) {
	var wire preparedConversationChangeWire
	if err := json.Unmarshal([]byte(data), &wire); err != nil {
		return nil, err
	}
	out := wire.PreparedConversationChange
	out.ConversationKey = wire.ConversationKey
	return &out, nil
}

// PrepareGroupLeave signs leaving a group: a removal of the sender, an admin
// add when PromoteAdminID is set, and a conversation delete. Leave does not
// rotate the conversation key.
func (c *Chat) PrepareGroupLeave(params GroupLeaveParams) (*PreparedAction, error) {
	return c.prepareAction(params, ffiPrepareGroupLeave)
}

// PrepareGroupTitleChange encrypts a new group title (plaintext NewTitle)
// under the conversation key and signs the change.
func (c *Chat) PrepareGroupTitleChange(params GroupTitleChangeParams) (*PreparedGroupMetadataChange, error) {
	return c.prepareMetadataChange(params, ffiPrepareGroupTitleChange)
}

// PrepareGroupAvatarChange signs a group avatar change: NewAvatarURL, the
// avatar image's media URL, as is, and ConversationKeyVersion, the version of
// the key the image is encrypted under. An empty ConversationKeyVersion signs
// the version of the conversation's newest key in the opt-in key cache
// (SetCacheKeys), the key the encrypt methods resolve; with no key cached
// the call fails with an ErrorKindInvalidState error.
func (c *Chat) PrepareGroupAvatarChange(params GroupAvatarChangeParams) (*PreparedAction, error) {
	return c.prepareAction(params, ffiPrepareGroupAvatarChange)
}

// PrepareGroupDescriptionChange encrypts a new group description (plaintext
// NewDescription) under the conversation key and signs the change.
func (c *Chat) PrepareGroupDescriptionChange(params GroupDescriptionChangeParams) (*PreparedGroupMetadataChange, error) {
	return c.prepareMetadataChange(params, ffiPrepareGroupDescriptionChange)
}

// PrepareGroupAdminsAdd signs adding group admins.
func (c *Chat) PrepareGroupAdminsAdd(params GroupAdminsAddParams) (*PreparedAction, error) {
	params.UserIDs = orEmpty(params.UserIDs)
	return c.prepareAction(params, ffiPrepareGroupAdminsAdd)
}

// PrepareGroupAdminsRemove signs removing group admins.
func (c *Chat) PrepareGroupAdminsRemove(params GroupAdminsRemoveParams) (*PreparedAction, error) {
	params.UserIDs = orEmpty(params.UserIDs)
	return c.prepareAction(params, ffiPrepareGroupAdminsRemove)
}

// PrepareGroupInviteEnable signs enabling a group invite. A nil expiry and an
// empty affiliate id sign null.
func (c *Chat) PrepareGroupInviteEnable(params GroupInviteEnableParams) (*PreparedAction, error) {
	return c.prepareAction(params, ffiPrepareGroupInviteEnable)
}

// PrepareGroupInviteDisable signs disabling a group invite. An empty
// DisabledBy uses the sender.
func (c *Chat) PrepareGroupInviteDisable(params GroupInviteDisableParams) (*PreparedAction, error) {
	return c.prepareAction(params, ffiPrepareGroupInviteDisable)
}

// PrepareGroupJoinRequest signs a request to join a group. An empty
// RequestingUserID uses the sender.
func (c *Chat) PrepareGroupJoinRequest(params GroupJoinRequestParams) (*PreparedAction, error) {
	return c.prepareAction(params, ffiPrepareGroupJoinRequest)
}

// PrepareGroupJoinReject signs rejecting group join requests.
func (c *Chat) PrepareGroupJoinReject(params GroupJoinRejectParams) (*PreparedAction, error) {
	params.UserIDs = orEmpty(params.UserIDs)
	return c.prepareAction(params, ffiPrepareGroupJoinReject)
}

// PrepareMessageTtlChange signs a message-TTL change. The signature covers
// the TTL only.
func (c *Chat) PrepareMessageTtlChange(params MessageTtlChangeParams) (*PreparedAction, error) {
	return c.prepareAction(params, ffiPrepareMessageTtlChange)
}

// PrepareMessageTtlRemove signs clearing a conversation's message TTL.
func (c *Chat) PrepareMessageTtlRemove(params MessageTtlRemoveParams) (*PreparedAction, error) {
	return c.prepareAction(params, ffiPrepareMessageTtlRemove)
}

// PrepareConversationMute signs muting or unmuting a conversation, group or
// one-to-one, for the signer alone: the action_signatures of the mute or
// unmute request, one entry. The event is signed for the signer's own
// "{sender}:{sender}" conversation and names the muted conversation in
// canonical colon form, the form the request must name it in. The SDK
// generates the action's message id; read it back from the entry.
func (c *Chat) PrepareConversationMute(params ConversationMuteParams) (*PreparedAction, error) {
	return c.prepareAction(params, ffiPrepareConversationMute)
}

// PrepareScreenCapture signs one screen-capture setting change.
func (c *Chat) PrepareScreenCapture(params ScreenCaptureParams) (*PreparedAction, error) {
	return c.prepareAction(params, ffiPrepareScreenCapture)
}

func (c *Chat) prepareMetadataChange(params any, call func(handle, string) (string, error)) (*PreparedGroupMetadataChange, error) {
	defer runtime.KeepAlive(c)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := call(c.h, string(j))
	if err != nil {
		return nil, err
	}
	var out PreparedGroupMetadataChange
	if err := json.Unmarshal([]byte(data), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Chat) prepareAction(params any, call func(handle, string) (string, error)) (*PreparedAction, error) {
	defer runtime.KeepAlive(c)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := call(c.h, string(j))
	if err != nil {
		return nil, err
	}
	var out PreparedAction
	if err := json.Unmarshal([]byte(data), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PrepareConversationArchive signs archiving or unarchiving a conversation,
// group or one-to-one: the action_signatures of the archive request
// (POST /2/chat/conversations/{id}/archive) or the unarchive request (DELETE
// on the same path), one entry. The SDK generates the action's message id;
// read it back from the entry.
func (c *Chat) PrepareConversationArchive(params ConversationArchiveParams) (*PreparedAction, error) {
	return c.prepareAction(params, ffiPrepareConversationArchive)
}

// PrepareMessageDelete builds the signed action for deleting messages from a
// conversation: the request's action_signatures, one entry.
//
// A delete is a signed plaintext event, not an encrypted message, so no
// conversation key is involved. The SDK generates the action's message id;
// read it back from the entry.
func (c *Chat) PrepareMessageDelete(params MessageDeleteParams) (*PreparedAction, error) {
	defer runtime.KeepAlive(c)
	// Sequence ids are a required field; marshal a nil slice as [] rather
	// than null.
	params.SequenceIDs = orEmpty(params.SequenceIDs)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := ffiPrepareMessageDelete(c.h, string(j))
	if err != nil {
		return nil, err
	}
	var out PreparedAction
	if err := json.Unmarshal([]byte(data), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PrepareMarkConversationRead builds the signed action for marking a
// conversation read: the action_signatures of the mark-read request
// (POST /2/chat/conversations/{id}/read), one entry.
//
// A read receipt is a signed plaintext event, not an encrypted message, so
// no conversation key is involved. The SDK generates the action's message
// id; read it back from the entry.
func (c *Chat) PrepareMarkConversationRead(params MarkConversationReadParams) (*PreparedAction, error) {
	defer runtime.KeepAlive(c)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := ffiPrepareMarkConversationRead(c.h, string(j))
	if err != nil {
		return nil, err
	}
	var out PreparedAction
	if err := json.Unmarshal([]byte(data), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DecryptEvent decrypts a single webhook event and errors on failure.
//
// Nil (or empty) ConversationKeys fall back to the opt-in conversation-key
// cache (SetCacheKeys); leave them nil for non-message events. Nil (or empty)
// SigningKeys fall back to the keys stored via SetSigningKeys,
// AddSigningKeys and AddPublicKeys; the SDK picks the sender's key for the
// version the event carries. With no signing keys passed or stored, every
// signed event fails under the default reject-unverified policy; only after
// SetRejectUnverified(false) are such events returned with Verified=false. A
// member removal's title and description, re-encrypted under the new key,
// aren't changes: they fail with an ErrorKindInvalidInput error under either
// policy.
//
// A key change that verifies is recorded as DecryptEvents records it: while
// the key cache is on, its key is cached, so later calls that omit their
// conversation key resolve it.
func (c *Chat) DecryptEvent(params DecryptEventParams) (*Event, error) {
	defer runtime.KeepAlive(c)
	params.ConversationKeys = orEmptyKeys(params.ConversationKeys)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := ffiDecryptEvent(c.h, string(j))
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
//
// The message id comes back in the payload's MessageID. A v1 message with
// files takes an id derived from its files, so building it again gives the
// same id; other messages take a random id. Encrypt each file afterwards
// with EncryptFile or FileEncryptor and the payload's EventB64.
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

// EncryptForward encrypts a forward of an existing message for the X API:
// a new message carrying the original's full text and entities, an
// optional comment, and the original's attachments uploaded again to this
// conversation. Its id and files work as in EncryptMessage.
func (c *Chat) EncryptForward(params EncryptForwardParams) (*SendPayload, error) {
	defer runtime.KeepAlive(c)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := ffiEncryptForward(c.h, string(j))
	if err != nil {
		return nil, err
	}
	var payload SendPayload
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

// EncryptReply encrypts a reply message for the X API. The reply's id and
// files work as in EncryptMessage.
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

// EncryptEdit encrypts a message edit for the X API.
func (c *Chat) EncryptEdit(params EncryptEditParams) (*SendPayload, error) {
	defer runtime.KeepAlive(c)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	data, err := ffiEncryptEdit(c.h, string(j))
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

// Decrypt decrypts a group title or description the X API returns for a
// conversation (base64 ciphertext) with the raw 32-byte conversation key.
// Group changes in events need no call of their own: DecryptEvent returns
// them decrypted.
func (c *Chat) Decrypt(ciphertextB64 string, conversationKey []byte) (string, error) {
	defer runtime.KeepAlive(c)
	return ffiDecrypt(c.h, ciphertextB64, base64.StdEncoding.EncodeToString(conversationKey))
}

// EncryptFile encrypts a file of an outgoing message, after the message is
// built. The SDK finds the attachment that names MediaHashKey in the message
// EventB64 carries, and encrypts the file under that attachment's key.
// Upload the result under the same media hash key; its size is
// EncryptedFileSize(len(File)). Errors say what to pass instead. Raw bytes
// in, raw bytes out; the FFI transports base64 internally.
func (c *Chat) EncryptFile(params EncryptFileParams) ([]byte, error) {
	defer runtime.KeepAlive(c)
	params.File = orEmptyBytes(params.File)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	outB64, err := ffiEncryptFile(c.h, string(j))
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(outB64)
}

// DecryptFile decrypts an encrypted file, as downloaded. Nil (or empty)
// ConversationKeys take the conversation's keys from the opt-in key cache
// (SetCacheKeys). Errors say what to pass instead. Raw bytes in, raw bytes
// out; the FFI transports base64 internally.
func (c *Chat) DecryptFile(params DecryptFileParams) ([]byte, error) {
	defer runtime.KeepAlive(c)
	params.Encrypted = orEmptyBytes(params.Encrypted)
	params.ConversationKeys = orEmptyKeys(params.ConversationKeys)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	outB64, err := ffiDecryptFile(c.h, string(j))
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(outB64)
}

// EncryptFileWithKey encrypts a file under a key you already hold, rather
// than from a message: a group's avatar image under the conversation key whose
// version is signed next to the avatar URL, or an app's own files at rest. The
// file is encrypted under the key itself, in the format EncryptFile writes;
// its size is EncryptedFileSize(len(File)). A key that is not 32 bytes is an
// ErrorKindInvalidInput error.
//
//	encrypted, err := chat.EncryptFileWithKey(chatxdk.EncryptFileWithKeyParams{
//	    File: image,
//	    Key:  conversationKey,
//	})
func (c *Chat) EncryptFileWithKey(params EncryptFileWithKeyParams) ([]byte, error) {
	defer runtime.KeepAlive(c)
	params.File = orEmptyBytes(params.File)
	params.Key = orEmptyBytes(params.Key)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	outB64, err := ffiEncryptFileWithKey(c.h, string(j))
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(outB64)
}

// DecryptFileWithKey decrypts a file encrypted under a key you already hold,
// as downloaded, such as a group's avatar image under the conversation key for
// the version its avatar change names. A key that is not 32 bytes is an
// ErrorKindInvalidInput error; bytes that are not the complete file encrypted
// under it are an ErrorKindDecryption error.
//
//	image, err := chat.DecryptFileWithKey(chatxdk.DecryptFileWithKeyParams{
//	    Encrypted: downloaded,
//	    Key:       conversationKey,
//	})
func (c *Chat) DecryptFileWithKey(params DecryptFileWithKeyParams) ([]byte, error) {
	defer runtime.KeepAlive(c)
	params.Encrypted = orEmptyBytes(params.Encrypted)
	params.Key = orEmptyBytes(params.Key)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	outB64, err := ffiDecryptFileWithKey(c.h, string(j))
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(outB64)
}

// FileEncryptor is an incremental encryptor for one file of an outgoing
// message.
//
// Feed the file in chunks with Push; call Finish once to emit the final
// frame. Always call Close to release the handle.
type FileEncryptor struct {
	h fileEncryptorHandle
}

// FileEncryptor creates an incremental encryptor for a file too large to
// hold in memory. It takes the params of EncryptFile apart from the file,
// which is fed to Push.
func (c *Chat) FileEncryptor(params FileEncryptorParams) (*FileEncryptor, error) {
	defer runtime.KeepAlive(c)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	h, err := ffiFileEncryptorNew(c.h, string(j))
	if err != nil {
		return nil, err
	}
	e := &FileEncryptor{h: h}
	// GC backstop for encryptors never explicitly Closed. A receiver becomes
	// collectible as soon as its last use passes — even while one of its
	// methods is still executing native code — so every method that hands
	// e.h to cgo defers runtime.KeepAlive(e), keeping this finalizer from
	// freeing the handle (live secretstream key state) mid-call.
	runtime.SetFinalizer(e, func(e *FileEncryptor) { e.Close() })
	return e, nil
}

// Push encrypts a chunk of the file, returning the encrypted bytes available
// so far (may be empty for small inputs).
func (e *FileEncryptor) Push(plaintext []byte) ([]byte, error) {
	defer runtime.KeepAlive(e)
	outB64, err := ffiFileEncryptorPush(e.h, base64.StdEncoding.EncodeToString(plaintext))
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(outB64)
}

// Finish emits the final frame and consumes the encryptor. Call Close
// afterwards to release the handle.
func (e *FileEncryptor) Finish() ([]byte, error) {
	defer runtime.KeepAlive(e)
	outB64, err := ffiFileEncryptorFinish(e.h)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(outB64)
}

// Close releases the underlying handle. Safe to call more than once.
func (e *FileEncryptor) Close() {
	defer runtime.KeepAlive(e)
	if e.h != nil {
		ffiFileEncryptorFree(e.h)
		e.h = nil
		runtime.SetFinalizer(e, nil)
	}
}

// FileDecryptor is an incremental decryptor for one encrypted file.
//
// Feed the encrypted bytes in chunks with Push; call Finish once at end of
// input. Finish errors if the file ended before its final frame
// (truncation), so do not treat bytes from Push as complete until Finish
// succeeds. Always call Close to release the handle.
type FileDecryptor struct {
	h fileDecryptorHandle
}

// FileDecryptor creates an incremental decryptor for an encrypted file too
// large to hold in memory. It takes the params of DecryptFile apart from the
// encrypted bytes, which are fed to Push.
func (c *Chat) FileDecryptor(params FileDecryptorParams) (*FileDecryptor, error) {
	defer runtime.KeepAlive(c)
	params.ConversationKeys = orEmptyKeys(params.ConversationKeys)
	j, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	h, err := ffiFileDecryptorNew(c.h, string(j))
	if err != nil {
		return nil, err
	}
	d := &FileDecryptor{h: h}
	// GC backstop for decryptors never explicitly Closed. A receiver becomes
	// collectible as soon as its last use passes — even while one of its
	// methods is still executing native code — so every method that hands
	// d.h to cgo defers runtime.KeepAlive(d), keeping this finalizer from
	// freeing the handle (live secretstream key state) mid-call.
	runtime.SetFinalizer(d, func(d *FileDecryptor) { d.Close() })
	return d, nil
}

// Push decrypts a chunk of the encrypted file, returning the bytes available
// so far (may be empty until enough input has arrived).
func (d *FileDecryptor) Push(ciphertext []byte) ([]byte, error) {
	defer runtime.KeepAlive(d)
	outB64, err := ffiFileDecryptorPush(d.h, base64.StdEncoding.EncodeToString(ciphertext))
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(outB64)
}

// Finish decrypts the final frame and consumes the decryptor. Call Close
// afterwards to release the handle.
func (d *FileDecryptor) Finish() ([]byte, error) {
	defer runtime.KeepAlive(d)
	outB64, err := ffiFileDecryptorFinish(d.h)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(outB64)
}

// Close releases the underlying handle. Safe to call more than once.
func (d *FileDecryptor) Close() {
	defer runtime.KeepAlive(d)
	if d.h != nil {
		ffiFileDecryptorFree(d.h)
		d.h = nil
		runtime.SetFinalizer(d, nil)
	}
}

// Sign signs application data with the signing key.
// Returns the raw 64-byte ECDSA P-256 signature, or an error for an event
// signature payload or a public key, which only the SDK signs.
func (c *Chat) Sign(data []byte) ([]byte, error) {
	defer runtime.KeepAlive(c)
	sigB64, err := ffiSign(c.h, data)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(sigB64)
}

// Verify verifies a raw signature (from Sign) against a base64-encoded
// signing public key. A malformed public key or signature is an error of
// kind ErrorKindInvalidInput. Needs no loaded keys.
func (c *Chat) Verify(publicKeyB64 string, signature, data []byte) (bool, error) {
	defer runtime.KeepAlive(c)
	return ffiVerify(c.h, publicKeyB64, base64.StdEncoding.EncodeToString(signature), data)
}

// VerifyKeyBinding verifies that a signing key is authentically bound to an
// identity key. Call this when you receive another user's public keys from
// the X API to detect server-side key substitution. All arguments are
// base64-encoded.
func (c *Chat) VerifyKeyBinding(identityPublicKeyB64, signingPublicKeyB64, identityPublicKeySignatureB64 string) (bool, error) {
	defer runtime.KeepAlive(c)
	return ffiVerifyKeyBinding(c.h, identityPublicKeyB64, signingPublicKeyB64, identityPublicKeySignatureB64)
}

// MatchesRegisteredKey reports whether the loaded identity public key is the
// key in publicKeyB64. The X API returns the identity public key in SPKI/DER
// encoding while GetPublicKeys returns the raw SEC1 point; this accepts
// either encoding, so use it to check whether the keys on this device belong
// to a key registered to the account.
func (c *Chat) MatchesRegisteredKey(publicKeyB64 string) (bool, error) {
	defer runtime.KeepAlive(c)
	return ffiMatchesRegisteredKey(c.h, publicKeyB64)
}
