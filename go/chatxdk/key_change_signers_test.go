package chatxdk

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// DecryptEvents and the key changes of a batch: a key change needs its
// signer's keys to verify, the result says which key changes did not verify
// or could not be decrypted and why, and keys and the version to encrypt with
// are reported per conversation.

const (
	// signerEnforcedSequence is a sequence id past the cut-over, where a key
	// change that does not verify has its key dropped.
	signerEnforcedSequence = "2100000000000000000"
	// signerUnenforcedSequence is a sequence id before the cut-over, where
	// the key is kept.
	signerUnenforcedSequence = "100"
	signerGroup              = "g900"
	signerOtherGroup         = "g901"
	signerThirdGroup         = "g902"
	signerKeyVersion         = "1"
)

// thriftStringField is a Thrift string field: its id, then the value's length
// and bytes.
func thriftStringField(id uint16, value string) []byte {
	field := binary.BigEndian.AppendUint16([]byte{11}, id)
	field = binary.BigEndian.AppendUint32(field, uint32(len(value)))
	return append(field, value...)
}

// thriftStructField is a Thrift struct field: its id, then the struct as
// already serialized.
func thriftStructField(id uint16, body []byte) []byte {
	return append(binary.BigEndian.AppendUint16([]byte{12}, id), body...)
}

// deliveredAction returns a signed action as delivered: the event the server
// relays for action, an entry of a prepared change's ActionSignatures, from
// senderID in conversationID, with the sequence id the server assigns.
func deliveredAction(t *testing.T, action ActionSignature, senderID, conversationID, sequenceID string) string {
	t.Helper()
	signed := action.MessageEventSignature
	var signature []byte
	signature = append(signature, thriftStringField(1, signed.Signature)...)
	signature = append(signature, thriftStringField(2, signed.PublicKeyVersion)...)
	signature = append(signature, thriftStringField(3, signed.SignatureVersion)...)
	signature = append(signature, 0)
	var event []byte
	event = append(event, thriftStringField(1, sequenceID)...)
	event = append(event, thriftStringField(2, action.MessageID)...)
	event = append(event, thriftStringField(3, senderID)...)
	event = append(event, thriftStringField(4, conversationID)...)
	event = append(event, thriftStructField(7, mustDecodeB64(t, action.EncodedMessageEventDetail))...)
	event = append(event, thriftStructField(9, signature)...)
	event = append(event, 0)
	return base64.StdEncoding.EncodeToString(event)
}

// signerParty is a chat with fresh keys as a user, and the keys others hold
// for it.
type signerParty struct {
	chat       *Chat
	userID     string
	signingKey SigningKeyEntry
	publicKey  PublicKeyInput
}

func newSignerParty(t *testing.T, userID string) *signerParty {
	t.Helper()
	chat := New()
	t.Cleanup(chat.Close)
	payload, err := chat.GenerateKeypairs()
	if err != nil {
		t.Fatalf("GenerateKeypairs failed: %v", err)
	}
	registration := payload.PublicKey
	return &signerParty{
		chat:   chat,
		userID: userID,
		signingKey: SigningKeyEntry{
			UserID:                     userID,
			PublicKeyVersion:           signerKeyVersion,
			PublicKey:                  registration.SigningPublicKey,
			IdentityPublicKey:          registration.PublicKey,
			IdentityPublicKeySignature: registration.IdentityPublicKeySignature,
		},
		publicKey: PublicKeyInput{
			UserID:            userID,
			IdentityPublicKey: registration.PublicKey,
			PublicKeyVersion:  signerKeyVersion,
		},
	}
}

// signedKeyChange is a key change as delivered, with its key.
type signedKeyChange struct {
	action         ActionSignature
	signerID       string
	conversationID string
	eventB64       string
	key            []byte
	version        string
}

// atVersion is the key change as delivered before the cut-over with its key
// version rewritten to version. The signature no longer verifies, and the key
// is kept.
func (c signedKeyChange) atVersion(t *testing.T, version string) signedKeyChange {
	t.Helper()
	detail := mustDecodeB64(t, c.action.EncodedMessageEventDetail)
	if len(version) != len(c.version) || !bytes.Contains(detail, []byte(c.version)) {
		t.Fatalf("cannot rewrite key version %q to %q", c.version, version)
	}
	action := c.action
	action.EncodedMessageEventDetail = base64.StdEncoding.EncodeToString(
		bytes.Replace(detail, []byte(c.version), []byte(version), 1))
	c.eventB64 = deliveredAction(t, action, c.signerID, c.conversationID, signerUnenforcedSequence)
	c.version = version
	return c
}

// newSignedKeyChange is the key change signer makes in conversationID for
// members.
func newSignedKeyChange(t *testing.T, signer *signerParty, members []*signerParty, conversationID string) signedKeyChange {
	t.Helper()
	publicKeys := make([]PublicKeyInput, len(members))
	for i, member := range members {
		publicKeys[i] = member.publicKey
	}
	prepared, err := signer.chat.PrepareConversationKeyChange(ConversationKeyChangeParams{
		SenderID:          signer.userID,
		SigningKeyVersion: signerKeyVersion,
		PublicKeys:        publicKeys,
		ConversationID:    conversationID,
	})
	if err != nil {
		t.Fatalf("PrepareConversationKeyChange failed: %v", err)
	}
	action := prepared.ActionSignatures[0]
	return signedKeyChange{
		action:         action,
		signerID:       signer.userID,
		conversationID: conversationID,
		eventB64:       deliveredAction(t, action, signer.userID, conversationID, signerEnforcedSequence),
		key:            prepared.ConversationKey,
		version:        prepared.ConversationKeyVersion,
	}
}

// signerMessage is the message author sends in conversationID under the key
// of change, as delivered.
func signerMessage(t *testing.T, author *signerParty, conversationID string, change signedKeyChange, text string) string {
	t.Helper()
	payload, err := author.chat.EncryptMessage(EncryptMessageParams{
		ConversationID:         conversationID,
		Text:                   text,
		SenderID:               author.userID,
		SigningKeyVersion:      signerKeyVersion,
		ConversationKey:        change.key,
		ConversationKeyVersion: change.version,
	})
	if err != nil {
		t.Fatalf("EncryptMessage failed: %v", err)
	}
	return delivered(t, payload.EventB64, "2100000000000000001")
}

// signerPage is an admin who rotates a group's key, a member who sends a
// message under it, and the bot that receives both events.
type signerPage struct {
	admin, member, bot *signerParty
	change             signedKeyChange
	events             []string
}

func newSignerPage(t *testing.T) signerPage {
	t.Helper()
	admin := newSignerParty(t, "5001")
	member := newSignerParty(t, "5002")
	bot := newSignerParty(t, "5003")
	change := newSignedKeyChange(t, admin, []*signerParty{admin, member, bot}, signerGroup)
	return signerPage{
		admin:  admin,
		member: member,
		bot:    bot,
		change: change,
		events: []string{change.eventB64, signerMessage(t, member, signerGroup, change, "hello group")},
	}
}

// decrypt is the bot's DecryptEvents of events with the signing keys of
// signers.
func (p signerPage) decrypt(t *testing.T, events []string, signers ...*signerParty) *DecryptEventsResult {
	t.Helper()
	signingKeys := make([]SigningKeyEntry, len(signers))
	for i, signer := range signers {
		signingKeys[i] = signer.signingKey
	}
	return decryptWith(t, p.bot.chat, events, signingKeys)
}

func decryptWith(t *testing.T, chat *Chat, events []string, signingKeys []SigningKeyEntry) *DecryptEventsResult {
	t.Helper()
	result, err := chat.DecryptEvents(DecryptEventsParams{Events: events, SigningKeys: signingKeys})
	if err != nil {
		t.Fatalf("DecryptEvents failed: %v", err)
	}
	return result
}

// unverified is UnverifiedKeyChanges when the page's key change did not
// verify for reason and lost its key.
func (p signerPage) unverified(reason UnverifiedKeyChangeReason) map[string]UnverifiedKeyChange {
	conversationID, senderID, publicKeyVersion := signerGroup, "5001", signerKeyVersion
	return map[string]UnverifiedKeyChange{"0": {
		Reason:                 reason,
		KeyDropped:             true,
		ConversationID:         &conversationID,
		ConversationKeyVersion: p.change.version,
		SenderID:               &senderID,
		PublicKeyVersion:       &publicKeyVersion,
	}}
}

// otherKeyChange is a key change the page's admin makes for itself and the
// bot in the other group, at another key version than the page's.
func (p signerPage) otherKeyChange(t *testing.T) signedKeyChange {
	t.Helper()
	members := []*signerParty{p.admin, p.bot}
	other := newSignedKeyChange(t, p.admin, members, signerOtherGroup)
	for other.version == p.change.version {
		other = newSignedKeyChange(t, p.admin, members, signerOtherGroup)
	}
	return other
}

// messageTexts is the text of each message among a result's events.
func messageTexts(result *DecryptEventsResult) []string {
	var texts []string
	for _, decrypted := range result.Events {
		if message := decrypted.Event.AsMessage(); message != nil {
			texts = append(texts, message.Text())
		}
	}
	return texts
}

func assertEqual(t *testing.T, what string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s mismatch:\ngot  %+v\nwant %+v", what, got, want)
	}
}

func assertContains(t *testing.T, what, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Errorf("unexpected %s: %q", what, got)
	}
}

func TestDecryptEventsReportsKeyChangeWithoutItsSignersKeys(t *testing.T) {
	page := newSignerPage(t)

	// The bot holds the keys of the member who wrote the message, not of the
	// admin who made the key change.
	result := page.decrypt(t, page.events, page.member)

	if len(result.Events) != 0 {
		t.Errorf("expected no decrypted events, got %d", len(result.Events))
	}
	keys := result.ConversationKeys
	assertEqual(t, "keys", keys.Keys, map[string][]byte{})
	assertEqual(t, "keys by conversation", keys.KeysByConversation, map[string]map[string][]byte{})
	if keys.LatestVersion != nil {
		t.Errorf("expected no latest version, got %q", *keys.LatestVersion)
	}
	assertEqual(t, "latest versions", keys.LatestVersions, map[string]string{})
	assertEqual(t, "unverified key changes", result.UnverifiedKeyChanges,
		page.unverified(UnverifiedKeyChangeMissingSigningKey))
	assertEqual(t, "undecryptable key changes", result.UndecryptableKeyChanges, map[string]UndecryptableKeyChange{})
	assertEqual(t, "rejected signing keys", result.RejectedSigningKeys, map[string]RejectedSigningKey{})
	assertContains(t, "key change error", result.Errors["0"],
		"no signing key for sender 5001 at public_key_version 1")
	assertContains(t, "message error", result.Errors["1"],
		"no matching key found: the key change for that version, event 0 of the batch, did not verify")
}

func TestDecryptEventsReportsKeyChangeCheckedWithAnotherKey(t *testing.T) {
	page := newSignerPage(t)

	// A signing key under the admin's user id and key version that is not the
	// key the admin signed with.
	otherKey := newSignerParty(t, page.admin.userID)
	result := page.decrypt(t, page.events, page.member, otherKey)

	if len(result.Events) != 0 {
		t.Errorf("expected no decrypted events, got %d", len(result.Events))
	}
	assertEqual(t, "unverified key changes", result.UnverifiedKeyChanges,
		page.unverified(UnverifiedKeyChangeInvalidSignature))
	assertContains(t, "key change error", result.Errors["0"], "ECDSA mismatch")
}

func TestDecryptEventsReportsSigningKeyWithAnInvalidBinding(t *testing.T) {
	page := newSignerPage(t)

	// The admin's signing key with a binding signature that is not its
	// signature over the identity key.
	unbound := page.admin.signingKey
	unbound.IdentityPublicKeySignature = page.member.signingKey.IdentityPublicKeySignature
	result := decryptWith(t, page.bot.chat, page.events, []SigningKeyEntry{page.member.signingKey, unbound})

	if len(result.Events) != 0 {
		t.Errorf("expected no decrypted events, got %d", len(result.Events))
	}
	assertEqual(t, "rejected signing keys", result.RejectedSigningKeys, map[string]RejectedSigningKey{
		"1": {UserID: "5001", PublicKeyVersion: signerKeyVersion},
	})
	assertEqual(t, "unverified key changes", result.UnverifiedKeyChanges,
		page.unverified(UnverifiedKeyChangeRejectedSigningKey))
	assertContains(t, "key change error", result.Errors["0"],
		"the signing key given for sender 5001 at public_key_version 1 was rejected: its identity binding does not verify")
}

func TestDecryptEventsVerifiesKeyChangeWithItsSignersKeys(t *testing.T) {
	page := newSignerPage(t)

	result := page.decrypt(t, page.events, page.member, page.admin)

	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", result.Errors)
	}
	assertEqual(t, "unverified key changes", result.UnverifiedKeyChanges, map[string]UnverifiedKeyChange{})
	assertEqual(t, "undecryptable key changes", result.UndecryptableKeyChanges, map[string]UndecryptableKeyChange{})
	assertEqual(t, "rejected signing keys", result.RejectedSigningKeys, map[string]RejectedSigningKey{})
	if len(result.Events) != 2 || result.Events[0].Event.Type != "KeyChange" {
		t.Fatalf("expected a key change and a message, got %+v", result.Events)
	}
	assertEqual(t, "messages", messageTexts(result), []string{"hello group"})
	keys := result.ConversationKeys
	if keys.LatestVersion == nil || *keys.LatestVersion != page.change.version {
		t.Errorf("unexpected latest version: %v", keys.LatestVersion)
	}
	assertEqual(t, "latest versions", keys.LatestVersions, map[string]string{signerGroup: page.change.version})
	assertEqual(t, "keys", keys.Keys, map[string][]byte{page.change.version: page.change.key})
	assertEqual(t, "keys by conversation", keys.KeysByConversation, map[string]map[string][]byte{
		signerGroup: {page.change.version: page.change.key},
	})
}

func TestDecryptEventsReportsKeyChangeItCannotDecrypt(t *testing.T) {
	page := newSignerPage(t)

	// A key change made for the admin and the member only: a chat whose
	// identity is the bot's finds no key for its user in it.
	outsider := newSignerParty(t, page.bot.userID)
	if err := outsider.chat.SetIdentity(SetIdentityParams{UserID: page.bot.userID, SigningKeyVersion: signerKeyVersion}); err != nil {
		t.Fatalf("SetIdentity failed: %v", err)
	}
	change := newSignedKeyChange(t, page.admin, []*signerParty{page.admin, page.member}, signerGroup)
	events := []string{change.eventB64, signerMessage(t, page.member, signerGroup, change, "not for the bot")}
	result := decryptWith(t, outsider.chat, events, []SigningKeyEntry{page.member.signingKey, page.admin.signingKey})

	if len(result.Events) != 0 {
		t.Errorf("expected no decrypted events, got %d", len(result.Events))
	}
	assertEqual(t, "unverified key changes", result.UnverifiedKeyChanges, map[string]UnverifiedKeyChange{})
	conversationID, senderID := signerGroup, "5001"
	assertEqual(t, "undecryptable key changes", result.UndecryptableKeyChanges, map[string]UndecryptableKeyChange{
		"0": {
			Reason:                 UndecryptableKeyChangeNotARecipient,
			ConversationID:         &conversationID,
			ConversationKeyVersion: change.version,
			SenderID:               &senderID,
		},
	})
	assertContains(t, "message error", result.Errors["1"],
		"event 0 of the batch, holds no key this chat can decrypt: it holds no key for this chat's user")
}

func TestDecryptEventsReportsKeysAndLatestVersionsPerConversation(t *testing.T) {
	page := newSignerPage(t)
	other := page.otherKeyChange(t)
	events := []string{page.change.eventB64, other.eventB64}
	versions := map[string]string{signerGroup: page.change.version, signerOtherGroup: other.version}
	keysByConversation := map[string]map[string][]byte{
		signerGroup:      {page.change.version: page.change.key},
		signerOtherGroup: {other.version: other.key},
	}

	// Each conversation has its own keys and its own version to encrypt
	// with, and no single version stands for both.
	keys := page.decrypt(t, events, page.admin).ConversationKeys
	assertEqual(t, "latest versions", keys.LatestVersions, versions)
	if keys.LatestVersion != nil {
		t.Errorf("expected no single latest version, got %q", *keys.LatestVersion)
	}
	assertEqual(t, "keys by conversation", keys.KeysByConversation, keysByConversation)
	assertEqual(t, "keys", keys.Keys, map[string][]byte{
		page.change.version: page.change.key,
		other.version:       other.key,
	})

	keys = page.decrypt(t, []string{other.eventB64}, page.admin).ConversationKeys
	if keys.LatestVersion == nil || *keys.LatestVersion != other.version {
		t.Errorf("unexpected latest version: %v", keys.LatestVersion)
	}
	assertEqual(t, "latest versions", keys.LatestVersions, map[string]string{signerOtherGroup: other.version})

	// A batch of two conversations has no single version even when only one
	// of them has a verified key change.
	stray := signerMessage(t, page.admin, signerThirdGroup, other, "hello third group")
	keys = page.decrypt(t, []string{page.change.eventB64, stray}, page.admin).ConversationKeys
	if keys.LatestVersion != nil {
		t.Errorf("expected no single latest version, got %q", *keys.LatestVersion)
	}
	assertEqual(t, "latest versions", keys.LatestVersions, map[string]string{signerGroup: page.change.version})

	// ExtractConversationKeys checks no signature, and reports the same way.
	extracted, err := page.bot.chat.ExtractConversationKeys(events)
	if err != nil {
		t.Fatalf("ExtractConversationKeys failed: %v", err)
	}
	assertEqual(t, "latest versions", extracted.LatestVersions, versions)
	if extracted.LatestVersion != nil {
		t.Errorf("expected no single latest version, got %q", *extracted.LatestVersion)
	}
	assertEqual(t, "keys by conversation", extracted.KeysByConversation, keysByConversation)
	extracted, err = page.bot.chat.ExtractConversationKeys([]string{other.eventB64})
	if err != nil {
		t.Fatalf("ExtractConversationKeys failed: %v", err)
	}
	if extracted.LatestVersion == nil || *extracted.LatestVersion != other.version {
		t.Errorf("unexpected latest version: %v", extracted.LatestVersion)
	}
}

func TestDecryptEventsKeepsKeysOfTwoConversationsAtOneVersionApart(t *testing.T) {
	page := newSignerPage(t)
	other := page.otherKeyChange(t)
	sameVersion := other.atVersion(t, page.change.version)
	events := []string{
		page.change.eventB64,
		sameVersion.eventB64,
		signerMessage(t, page.admin, signerGroup, page.change, "hello group"),
		signerMessage(t, page.admin, signerOtherGroup, sameVersion, "hello other group"),
	}

	// Each message decrypts under its own conversation's key, and a lookup
	// by version alone finds neither.
	result := page.decrypt(t, events, page.admin)
	assertEqual(t, "messages", messageTexts(result), []string{"hello group", "hello other group"})
	var failed []string
	for index := range result.Errors {
		failed = append(failed, index)
	}
	sort.Strings(failed)
	assertEqual(t, "failed events", failed, []string{"1"})
	assertEqual(t, "keys by conversation", result.ConversationKeys.KeysByConversation, map[string]map[string][]byte{
		signerGroup:      {page.change.version: page.change.key},
		signerOtherGroup: {page.change.version: other.key},
	})
	assertEqual(t, "keys", result.ConversationKeys.Keys, map[string][]byte{})
	unverified := result.UnverifiedKeyChanges["1"]
	if unverified.Reason != UnverifiedKeyChangeInvalidSignature || unverified.KeyDropped {
		t.Errorf("unexpected unverified key change: %+v", unverified)
	}
}
