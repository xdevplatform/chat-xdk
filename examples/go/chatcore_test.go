package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/xdevplatform/chat-xdk/go/chatxdk"
)

type vectors struct {
	PrivateKeysConcatB64          string `json:"private_keys_concat_b64"`
	ConversationKeyB64            string `json:"conversation_key_b64"`
	IdentityPublicB64             string `json:"identity_public_b64"`
	SigningPublicB64              string `json:"signing_public_b64"`
	IdentityPublicKeySignatureB64 string `json:"identity_public_key_signature_b64"`
	EventKeyChangeB64             string `json:"event_key_change_b64"`
	EventMessageB64               string `json:"event_message_b64"`
	EventSenderID                 string `json:"event_sender_id"`
	EventConversationID           string `json:"event_conversation_id"`
	EventConversationKeyVersion   string `json:"event_conversation_key_version"`
	EventSigningKeyVersion        string `json:"event_signing_key_version"`
	EventRecipientKeyVersion      string `json:"event_recipient_key_version"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// examples/go/chatcore_test.go -> repo root is two directories up.
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")
	data, err := os.ReadFile(filepath.Join(root, "tests", "fixtures", "sdk_vectors.json"))
	if err != nil {
		t.Fatalf("read sdk_vectors.json: %v", err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse sdk_vectors.json: %v", err)
	}
	return v
}

// conversationKey decodes the fixture's base64 conversation key into the raw
// bytes the SDK's key-typed APIs take.
func (v vectors) conversationKey(t *testing.T) []byte {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(v.ConversationKeyB64)
	if err != nil {
		t.Fatalf("decode conversation_key_b64: %v", err)
	}
	return key
}

func loadedCore(t *testing.T) (*ChatCore, vectors) {
	t.Helper()
	v := loadVectors(t)
	core := NewChatCore()
	if err := core.LoadKeys(v.PrivateKeysConcatB64, v.EventRecipientKeyVersion); err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}
	// The session identity stands in for every sender argument; the fixture
	// sender id matches the committed event vectors.
	if err := core.SetIdentity(v.EventSenderID); err != nil {
		t.Fatalf("SetIdentity: %v", err)
	}
	return core, v
}

func TestLoadKeysMatchesFixture(t *testing.T) {
	core, v := loadedCore(t)
	defer core.Close()
	keys, err := core.PublicKeys()
	if err != nil {
		t.Fatalf("PublicKeys: %v", err)
	}
	if keys.Identity != v.IdentityPublicB64 {
		t.Errorf("identity mismatch:\ngot  %s\nwant %s", keys.Identity, v.IdentityPublicB64)
	}
	if keys.Signing != v.SigningPublicB64 {
		t.Errorf("signing mismatch:\ngot  %s\nwant %s", keys.Signing, v.SigningPublicB64)
	}
}

func TestGenericEncryptDecryptRoundtrip(t *testing.T) {
	core, v := loadedCore(t)
	defer core.Close()
	plaintext := "hello from the go example"
	ct, err := core.Encrypt(plaintext, v.conversationKey(t))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if ct == plaintext {
		t.Fatal("ciphertext equals plaintext")
	}
	got, err := core.Decrypt(ct, v.conversationKey(t))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != plaintext {
		t.Errorf("roundtrip mismatch:\ngot  %q\nwant %q", got, plaintext)
	}
}

func TestConversationKeyRoundtrip(t *testing.T) {
	core, v := loadedCore(t)
	defer core.Close()
	prepared, err := core.PrepareConversationKeyChange([]chatxdk.PublicKeyInput{
		{UserID: "me", PublicKey: v.IdentityPublicB64, KeyVersion: "1"},
	}, "conv-1")
	if err != nil {
		t.Fatalf("PrepareConversationKeyChange: %v", err)
	}
	if len(prepared.ParticipantKeys) != 1 {
		t.Fatalf("expected 1 participant key, got %d", len(prepared.ParticipantKeys))
	}
	got, err := core.DecryptConversationKey(prepared.ParticipantKeys[0].EncryptedKey)
	if err != nil {
		t.Fatalf("DecryptConversationKey: %v", err)
	}
	if !bytes.Equal(got, prepared.ConversationKey) {
		t.Errorf("conversation key roundtrip mismatch:\ngot  %x\nwant %x", got, prepared.ConversationKey)
	}
}

func TestEncryptReplyProducesPayload(t *testing.T) {
	core, v := loadedCore(t)
	defer core.Close()
	body, err := core.EncryptReply("6789:12345", "pong", &ReplyOptions{
		ConversationKey:        v.conversationKey(t),
		ConversationKeyVersion: "1710000000000",
	})
	if err != nil {
		t.Fatalf("EncryptReply: %v", err)
	}
	if body.EncodedMessageCreateEvent == "" {
		t.Error("empty encoded_message_create_event")
	}
	if body.EncodedMessageEventSignature == "" {
		t.Error("empty encoded_message_event_signature")
	}
	if body.MessageID == "" {
		t.Error("empty message_id")
	}
}

func TestDecryptBatchEmptyIsSafe(t *testing.T) {
	core, _ := loadedCore(t)
	defer core.Close()
	result, err := core.DecryptBatch([]string{}, nil)
	if err != nil {
		t.Fatalf("DecryptBatch: %v", err)
	}
	if len(result.Messages) != 0 {
		t.Errorf("expected no messages, got %d", len(result.Messages))
	}
}

func TestDecryptOneRejectsGarbage(t *testing.T) {
	core, _ := loadedCore(t)
	defer core.Close()
	if _, err := core.DecryptOne("not-valid-base64!!!", map[string][]byte{}, nil); err == nil {
		t.Error("expected error for invalid base64 event")
	}
}

// fixtureKeys returns the flat public-key entries the prepare methods take,
// built from the fixture identity key.
func fixtureKeys(v vectors) []chatxdk.PublicKeyInput {
	return []chatxdk.PublicKeyInput{
		{UserID: "1000", PublicKey: v.IdentityPublicB64, KeyVersion: "1"},
	}
}

func TestPrepToRequestMapsTheRESTShape(t *testing.T) {
	// The mapper output is exactly what the X API's write endpoints take;
	// a drifted field name here breaks every flow in the live e2e.
	core, v := loadedCore(t)
	defer core.Close()
	prep, err := core.PrepareConversationKeyChange(fixtureKeys(v), "1000:2000")
	if err != nil {
		t.Fatalf("PrepareConversationKeyChange: %v", err)
	}
	keys, err := core.PublicKeys()
	if err != nil {
		t.Fatalf("PublicKeys: %v", err)
	}
	body := PrepToRequest(prep, keys.Signing)

	if body["conversation_key_version"] != prep.ConversationKeyVersion {
		t.Errorf("conversation_key_version mismatch: %v", body["conversation_key_version"])
	}
	pks := body["conversation_participant_keys"].([]map[string]any)
	if len(pks) != 1 {
		t.Fatalf("expected 1 participant key, got %d", len(pks))
	}
	for _, field := range []string{"encrypted_conversation_key", "public_key_version", "user_id"} {
		if pks[0][field] == "" {
			t.Errorf("empty participant key field %q", field)
		}
	}
	if len(pks[0]) != 3 {
		t.Errorf("unexpected participant key fields: %v", pks[0])
	}
	sigs := body["action_signatures"].([]map[string]any)
	if len(sigs) != 1 {
		t.Fatalf("expected 1 action signature, got %d", len(sigs))
	}
	sig := sigs[0]
	if sig["message_id"] != prep.ActionSignatures[0].MessageID {
		t.Errorf("message_id mismatch: %v", sig["message_id"])
	}
	if sig["encoded_message_event_detail"] == "" {
		t.Error("empty encoded_message_event_detail")
	}
	inner := sig["message_event_signature"].(map[string]any)
	if inner["signing_public_key"] != keys.Signing {
		t.Errorf("signing_public_key mismatch: %v", inner["signing_public_key"])
	}
	if inner["signature"] == "" || inner["public_key_version"] == "" {
		t.Errorf("incomplete message_event_signature: %v", inner)
	}
	// CKCE signature payloads are withheld (they embed the plaintext key).
	if _, present := sig["signature_payload"]; present {
		t.Error("signature_payload must be omitted for a key change")
	}
}

func TestPrepareGroupCreateYieldsTwoSignatures(t *testing.T) {
	core, v := loadedCore(t)
	defer core.Close()
	prep, err := core.PrepareGroupCreate(fixtureKeys(v), "g123", []string{"1000"}, []string{"1000"})
	if err != nil {
		t.Fatalf("PrepareGroupCreate: %v", err)
	}
	if len(prep.ActionSignatures) != 2 {
		t.Errorf("expected 2 action signatures, got %d", len(prep.ActionSignatures))
	}
	if len(prep.ConversationKey) != 32 {
		t.Errorf("expected a 32-byte conversation key, got %d bytes", len(prep.ConversationKey))
	}
}

func TestEncryptReactionProducesSendablePayload(t *testing.T) {
	// The reaction targets the fixture's raw message event; conversation id
	// and target sequence id derive from it.
	core, v := loadedCore(t)
	defer core.Close()
	body, err := core.EncryptAddReaction(v.EventMessageB64, "\U0001f44d", v.conversationKey(t), v.EventConversationKeyVersion)
	if err != nil {
		t.Fatalf("EncryptAddReaction: %v", err)
	}
	if body.MessageID == "" {
		t.Error("empty message_id")
	}
	if body.EncodedMessageCreateEvent == "" {
		t.Error("empty encoded_message_create_event")
	}
	if body.EncodedMessageEventSignature == "" {
		t.Error("empty encoded_message_event_signature")
	}
	if _, err := core.EncryptRemoveReaction(v.EventMessageB64, "\U0001f44d", v.conversationKey(t), v.EventConversationKeyVersion); err != nil {
		t.Fatalf("EncryptRemoveReaction: %v", err)
	}
}

func TestMediaStreamEncryptDecryptRoundtrip(t *testing.T) {
	// The chunked stream path the media flow uses: multi-chunk payload in,
	// identical bytes out, and truncation is detected.
	core, v := loadedCore(t)
	defer core.Close()
	key := v.conversationKey(t)
	plaintext := make([]byte, 300_000)
	for i := range plaintext {
		plaintext[i] = byte((i*31 + 7) % 256)
	}

	ciphertext, err := core.EncryptMedia(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptMedia: %v", err)
	}
	if bytes.Equal(ciphertext[:len(plaintext)], plaintext) {
		t.Fatal("ciphertext prefix equals plaintext")
	}
	decrypted, err := core.DecryptMedia(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptMedia: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("media round-trip did not return the original bytes")
	}

	if _, err := core.DecryptMedia(ciphertext[:len(ciphertext)-4], key); err == nil {
		t.Error("expected an error for a truncated stream")
	}
}

func TestThreadedReplyWithEntitiesAndTTL(t *testing.T) {
	// A threaded reply anchored on the fixture's raw message event, with an
	// explicit key override plus entities and a TTL.
	core, v := loadedCore(t)
	defer core.Close()
	body, err := core.EncryptReply(v.EventConversationID, "@user hello", &ReplyOptions{
		ReplyToEvent:           v.EventMessageB64,
		ConversationKey:        v.conversationKey(t),
		ConversationKeyVersion: v.EventConversationKeyVersion,
		Entities:               []chatxdk.EntityTuple{chatxdk.NewEntity(0, 5, "mention")},
		TTLMsec:                60_000,
	})
	if err != nil {
		t.Fatalf("EncryptReply: %v", err)
	}
	if body.EncodedMessageCreateEvent == "" {
		t.Error("empty encoded_message_create_event")
	}
}

// TestCachedKeyReplyFlow is the bot's send path end to end, offline: stored
// signing keys verify the fixture key change, the batch decrypt adopts its
// key into the SDK cache, and the reply-by-event needs neither a sender nor
// a conversation key argument.
func TestCachedKeyReplyFlow(t *testing.T) {
	core, v := loadedCore(t)
	defer core.Close()
	if err := core.SetSigningKeys([]chatxdk.SigningKeyEntry{{
		UserID:                     v.EventSenderID,
		PublicKeyVersion:           v.EventSigningKeyVersion,
		PublicKey:                  v.SigningPublicB64,
		IdentityPublicKey:          v.IdentityPublicB64,
		IdentityPublicKeySignature: v.IdentityPublicKeySignatureB64,
	}}); err != nil {
		t.Fatalf("SetSigningKeys: %v", err)
	}

	result, err := core.DecryptBatch([]string{v.EventKeyChangeB64, v.EventMessageB64}, nil)
	if err != nil {
		t.Fatalf("DecryptBatch: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected decrypt errors: %v", result.Errors)
	}

	body, err := core.EncryptReply(v.EventConversationID, "pong", &ReplyOptions{
		ReplyToEvent: v.EventMessageB64,
	})
	if err != nil {
		t.Fatalf("EncryptReply (cached key): %v", err)
	}
	if body.MessageID == "" || body.EncodedMessageCreateEvent == "" {
		t.Errorf("incomplete send body: %+v", body)
	}
}
