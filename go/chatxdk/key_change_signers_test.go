package chatxdk

import (
	"encoding/base64"
	"encoding/binary"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// DecryptEvents and the members who sign a batch's key changes: a key change
// needs its signer's keys to verify, the result says which key changes did
// not verify and why, and the version to encrypt with is reported per
// conversation.

const (
	// signerEnforcedSequence is a sequence id past the cut-over, where a key
	// change that does not verify has its key dropped.
	signerEnforcedSequence = "2100000000000000000"
	signerGroup            = "g900"
	signerOtherGroup       = "g901"
	signerKeyVersion       = "1"
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
	eventB64 string
	key      []byte
	version  string
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
	return signedKeyChange{
		eventB64: deliveredAction(t, prepared.ActionSignatures[0], signer.userID, conversationID, signerEnforcedSequence),
		key:      prepared.ConversationKey,
		version:  prepared.ConversationKeyVersion,
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
	result, err := p.bot.chat.DecryptEvents(DecryptEventsParams{Events: events, SigningKeys: signingKeys})
	if err != nil {
		t.Fatalf("DecryptEvents failed: %v", err)
	}
	return result
}

func TestDecryptEventsReportsKeyChangeWithoutItsSignersKeys(t *testing.T) {
	page := newSignerPage(t)

	// The bot holds the keys of the member who wrote the message, not of the
	// admin who made the key change.
	result := page.decrypt(t, page.events, page.member)

	if len(result.Events) != 0 {
		t.Errorf("expected no decrypted events, got %d", len(result.Events))
	}
	if len(result.ConversationKeys.Keys) != 0 {
		t.Errorf("expected the key to be dropped, got %d keys", len(result.ConversationKeys.Keys))
	}
	if result.ConversationKeys.LatestVersion != nil {
		t.Errorf("expected no latest version, got %q", *result.ConversationKeys.LatestVersion)
	}
	if len(result.ConversationKeys.LatestVersions) != 0 {
		t.Errorf("expected no latest versions, got %v", result.ConversationKeys.LatestVersions)
	}
	conversationID, senderID, publicKeyVersion := signerGroup, "5001", signerKeyVersion
	want := []UnverifiedKeyChange{{
		Index:                  0,
		Reason:                 UnverifiedKeyChangeMissingSigningKey,
		KeyDropped:             true,
		ConversationID:         &conversationID,
		ConversationKeyVersion: page.change.version,
		SenderID:               &senderID,
		PublicKeyVersion:       &publicKeyVersion,
	}}
	if !reflect.DeepEqual(result.UnverifiedKeyChanges, want) {
		t.Errorf("unverified key changes mismatch:\ngot  %+v\nwant %+v", result.UnverifiedKeyChanges, want)
	}
	if !strings.Contains(result.Errors["0"], "no signing key for sender 5001 at public_key_version 1") {
		t.Errorf("unexpected key change error: %q", result.Errors["0"])
	}
	if !strings.Contains(result.Errors["1"], "no matching key found: the key change for that version, event 0 of the batch, did not verify") {
		t.Errorf("unexpected message error: %q", result.Errors["1"])
	}
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
	if len(result.UnverifiedKeyChanges) != 1 {
		t.Fatalf("expected 1 unverified key change, got %+v", result.UnverifiedKeyChanges)
	}
	unverified := result.UnverifiedKeyChanges[0]
	if unverified.Reason != UnverifiedKeyChangeInvalidSignature || !unverified.KeyDropped {
		t.Errorf("unexpected unverified key change: %+v", unverified)
	}
	if !strings.Contains(result.Errors["0"], "ECDSA mismatch") {
		t.Errorf("unexpected key change error: %q", result.Errors["0"])
	}
}

func TestDecryptEventsVerifiesKeyChangeWithItsSignersKeys(t *testing.T) {
	page := newSignerPage(t)

	result := page.decrypt(t, page.events, page.member, page.admin)

	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", result.Errors)
	}
	if len(result.UnverifiedKeyChanges) != 0 {
		t.Errorf("expected no unverified key changes, got %+v", result.UnverifiedKeyChanges)
	}
	if len(result.Events) != 2 || result.Events[0].Event.Type != "KeyChange" {
		t.Fatalf("expected a key change and a message, got %+v", result.Events)
	}
	message := result.Events[1].Event.AsMessage()
	if message == nil || message.Text() != "hello group" {
		t.Errorf("unexpected message: %+v", message)
	}
	latest := result.ConversationKeys.LatestVersion
	if latest == nil || *latest != page.change.version {
		t.Errorf("unexpected latest version: %v", latest)
	}
	want := map[string]string{signerGroup: page.change.version}
	if !reflect.DeepEqual(result.ConversationKeys.LatestVersions, want) {
		t.Errorf("latest versions mismatch:\ngot  %v\nwant %v", result.ConversationKeys.LatestVersions, want)
	}
}

func TestDecryptEventsReportsLatestVersionsPerConversation(t *testing.T) {
	page := newSignerPage(t)
	members := []*signerParty{page.admin, page.bot}
	other := newSignedKeyChange(t, page.admin, members, signerOtherGroup)
	for other.version == page.change.version {
		other = newSignedKeyChange(t, page.admin, members, signerOtherGroup)
	}
	events := []string{page.change.eventB64, other.eventB64}
	versions := map[string]string{signerGroup: page.change.version, signerOtherGroup: other.version}

	// Each conversation has its own version to encrypt with, and no single
	// one stands for both.
	result := page.decrypt(t, events, page.admin)
	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", result.Errors)
	}
	if !reflect.DeepEqual(result.ConversationKeys.LatestVersions, versions) {
		t.Errorf("latest versions mismatch:\ngot  %v\nwant %v", result.ConversationKeys.LatestVersions, versions)
	}
	if result.ConversationKeys.LatestVersion != nil {
		t.Errorf("expected no single latest version, got %q", *result.ConversationKeys.LatestVersion)
	}

	result = page.decrypt(t, []string{other.eventB64}, page.admin)
	latest := result.ConversationKeys.LatestVersion
	if latest == nil || *latest != other.version {
		t.Errorf("unexpected latest version: %v", latest)
	}
	want := map[string]string{signerOtherGroup: other.version}
	if !reflect.DeepEqual(result.ConversationKeys.LatestVersions, want) {
		t.Errorf("latest versions mismatch:\ngot  %v\nwant %v", result.ConversationKeys.LatestVersions, want)
	}

	// ExtractConversationKeys checks no signature: its LatestVersion is the
	// batch's highest, and LatestVersions each conversation's.
	extracted, err := page.bot.chat.ExtractConversationKeys(events)
	if err != nil {
		t.Fatalf("ExtractConversationKeys failed: %v", err)
	}
	if !reflect.DeepEqual(extracted.LatestVersions, versions) {
		t.Errorf("latest versions mismatch:\ngot  %v\nwant %v", extracted.LatestVersions, versions)
	}
	first, err := strconv.ParseInt(page.change.version, 10, 64)
	if err != nil {
		t.Fatalf("conversation key version %q: %v", page.change.version, err)
	}
	second, err := strconv.ParseInt(other.version, 10, 64)
	if err != nil {
		t.Fatalf("conversation key version %q: %v", other.version, err)
	}
	highest := strconv.FormatInt(max(first, second), 10)
	if extracted.LatestVersion == nil || *extracted.LatestVersion != highest {
		t.Errorf("unexpected latest version: %v, want %q", extracted.LatestVersion, highest)
	}
}
