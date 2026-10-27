package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	// A message sent under a per-message key, with two media attachments
	// encrypted by another client.
	EventMessageKeyB64               string `json:"event_message_key_b64"`
	MessageKeyConversationKeyHex     string `json:"message_key_conversation_key_hex"`
	MessageKeyConversationKeyVersion string `json:"message_key_conversation_key_version"`
	MediaFirstHashKey                string `json:"media_first_hash_key"`
	MediaFirstEncryptedB64           string `json:"media_first_encrypted_b64"`
	MediaFirstPlaintextB64           string `json:"media_first_plaintext_b64"`
	MediaSecondHashKey               string `json:"media_second_hash_key"`
	MediaSecondEncryptedB64          string `json:"media_second_encrypted_b64"`
	MediaSecondPlaintextB64          string `json:"media_second_plaintext_b64"`
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

// Freshly generated keys have no registered version yet, so the bot cannot
// sign as itself until LoadKeys provides one.
func TestSetIdentityNeedsTheRegisteredVersion(t *testing.T) {
	core := NewChatCore()
	defer core.Close()
	if _, _, err := core.GenerateAndRegister(); err != nil {
		t.Fatalf("GenerateAndRegister: %v", err)
	}
	err := core.SetIdentity("12345")
	if err == nil || !strings.Contains(err.Error(), "signing key version unknown") {
		t.Fatalf("SetIdentity without a version: got %v", err)
	}
}

func TestGroupTitleChangeEncryptsTheTitleItSigns(t *testing.T) {
	core, v := loadedCore(t)
	defer core.Close()
	title := "hello from the go example"
	prepared, err := core.PrepareGroupTitleChange("g123", title, v.conversationKey(t), "1")
	if err != nil {
		t.Fatalf("PrepareGroupTitleChange: %v", err)
	}
	if prepared.EncryptedValue == title || prepared.ConversationKeyVersion != "1" {
		t.Fatalf("unexpected title change: %+v", prepared)
	}
	got, err := core.Decrypt(prepared.EncryptedValue, v.conversationKey(t))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != title {
		t.Errorf("roundtrip mismatch:\ngot  %q\nwant %q", got, title)
	}
}

func TestConversationKeyRoundtrip(t *testing.T) {
	core, v := loadedCore(t)
	defer core.Close()
	prepared, err := core.PrepareConversationKeyChange([]chatxdk.PublicKeyInput{
		{UserID: "910002", PublicKey: v.IdentityPublicB64, KeyVersion: "1"},
	}, "conv-1")
	if err != nil {
		t.Fatalf("PrepareConversationKeyChange: %v", err)
	}
	if len(prepared.ConversationParticipantKeys) != 1 {
		t.Fatalf("expected 1 participant key, got %d", len(prepared.ConversationParticipantKeys))
	}
	got, err := core.DecryptConversationKey(prepared.ConversationParticipantKeys[0].EncryptedConversationKey)
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
	if body.XdkVersion == "" {
		t.Error("empty xdk_version")
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
	// Inspect the JSON the X API receives.
	data, err := json.Marshal(PrepToRequest(prep))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var body struct {
		ConversationKeyVersion      string           `json:"conversation_key_version"`
		ConversationParticipantKeys []map[string]any `json:"conversation_participant_keys"`
		ActionSignatures            []map[string]any `json:"action_signatures"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if body.ConversationKeyVersion != prep.ConversationKeyVersion {
		t.Errorf("conversation_key_version mismatch: %v", body.ConversationKeyVersion)
	}
	pks := body.ConversationParticipantKeys
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
	sigs := body.ActionSignatures
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
}

func TestRemovalToRequestRotatesForMembersWhoStay(t *testing.T) {
	core, v := loadedCore(t)
	defer core.Close()
	prep, err := core.PrepareGroupMembersRemove(fixtureKeys(v), "g123", []string{"2000"})
	if err != nil {
		t.Fatalf("PrepareGroupMembersRemove: %v", err)
	}
	data, err := json.Marshal(RemovalToRequest([]string{"2000"}, prep))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var body struct {
		UserIDs                []string         `json:"user_ids"`
		ActionSignatures       []map[string]any `json:"action_signatures"`
		ConversationKeyVersion string           `json:"conversation_key_version"`
		GroupKeyRotationData   struct {
			ConversationKeyVersion      string           `json:"conversation_key_version"`
			ConversationParticipantKeys []map[string]any `json:"conversation_participant_keys"`
		} `json:"group_key_rotation_data"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.UserIDs) != 1 || body.UserIDs[0] != "2000" {
		t.Errorf("user_ids: %v", body.UserIDs)
	}
	if len(body.ActionSignatures) != 2 {
		t.Fatalf("expected 2 action signatures, got %d", len(body.ActionSignatures))
	}
	if body.ConversationKeyVersion != "" {
		t.Errorf("top-level conversation_key_version %q", body.ConversationKeyVersion)
	}
	if body.GroupKeyRotationData.ConversationKeyVersion != prep.ConversationKeyVersion {
		t.Errorf("rotation version: %s", body.GroupKeyRotationData.ConversationKeyVersion)
	}
	pks := body.GroupKeyRotationData.ConversationParticipantKeys
	if len(pks) != 1 {
		t.Fatalf("expected 1 participant key, got %d", len(pks))
	}
	if pks[0]["user_id"] != "1000" {
		t.Errorf("participant user_id: %v", pks[0]["user_id"])
	}
	for _, field := range []string{"encrypted_conversation_key", "public_key_version", "user_id"} {
		if pks[0][field] == "" {
			t.Errorf("empty participant key field %q", field)
		}
	}
}

func TestPrepareGroupCreateYieldsTwoSignatures(t *testing.T) {
	core, v := loadedCore(t)
	defer core.Close()
	title := "hello from the go example"
	prep, err := core.PrepareGroupCreate(fixtureKeys(v), "g123", []string{"1000"}, []string{"1000"}, title)
	if err != nil {
		t.Fatalf("PrepareGroupCreate: %v", err)
	}
	if len(prep.ActionSignatures) != 2 {
		t.Fatalf("expected 2 action signatures, got %d", len(prep.ActionSignatures))
	}
	if len(prep.ConversationKey) != 32 {
		t.Errorf("expected a 32-byte conversation key, got %d bytes", len(prep.ConversationKey))
	}
	// The title goes out encrypted under the new key: the group_name the
	// create request sends, and the ciphertext the create signs.
	if prep.EncryptedTitle == nil {
		t.Fatal("expected an encrypted title")
	}
	got, err := core.Decrypt(*prep.EncryptedTitle, prep.ConversationKey)
	if err != nil || got != title {
		t.Errorf("encrypted title decrypts to %q, %v", got, err)
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
	if body.XdkVersion == "" {
		t.Error("empty xdk_version")
	}
	if _, err := core.EncryptRemoveReaction(v.EventMessageB64, "\U0001f44d", v.conversationKey(t), v.EventConversationKeyVersion); err != nil {
		t.Fatalf("EncryptRemoveReaction: %v", err)
	}
}

func TestMediaEncryptDecryptRoundtrip(t *testing.T) {
	// The message-first media flow: the message names the file by the media
	// hash key its upload started with, the file is encrypted from the
	// message's EventB64 in chunks, and it decrypts through that event. A
	// truncated file is detected.
	core, v := loadedCore(t)
	defer core.Close()
	key := v.conversationKey(t)
	keys := map[string][]byte{"1": key}
	plaintext := make([]byte, 300_000)
	for i := range plaintext {
		plaintext[i] = byte((i*31 + 7) % 256)
	}
	mediaType := int32(5)
	body, err := core.EncryptReply("1000:2000", "a photo", &ReplyOptions{
		ConversationKey:        key,
		ConversationKeyVersion: "1",
		Attachments: []chatxdk.AttachmentDescriptor{{
			AttachmentType: "media",
			MediaHashKey:   "photo",
			Width:          4,
			Height:         3,
			FilesizeBytes:  int64(len(plaintext)),
			Filename:       "photo.bin",
			MediaType:      &mediaType,
		}},
	})
	if err != nil {
		t.Fatalf("EncryptReply (media): %v", err)
	}
	if body.EventB64 == "" {
		t.Fatal("empty event_b64")
	}

	ciphertext, err := core.EncryptMedia(plaintext, body.EventB64, key, "1", "photo")
	if err != nil {
		t.Fatalf("EncryptMedia: %v", err)
	}
	size, err := chatxdk.EncryptedFileSize(uint64(len(plaintext)))
	if err != nil {
		t.Fatalf("EncryptedFileSize: %v", err)
	}
	if uint64(len(ciphertext)) != size {
		t.Errorf("encrypted size %d, want %d", len(ciphertext), size)
	}
	decrypted, err := core.DecryptMedia(ciphertext, body.EventB64, keys, "photo")
	if err != nil {
		t.Fatalf("DecryptMedia: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("media round-trip did not return the original bytes")
	}

	_, err = core.DecryptMedia(ciphertext[:len(ciphertext)-4], body.EventB64, keys, "photo")
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Errorf("expected a truncation error, got %v", err)
	}
}

func TestMediaFromTheFixtureMessageOpens(t *testing.T) {
	// Media encrypted by another client opens through its message's event.
	core, v := loadedCore(t)
	defer core.Close()
	key, err := hex.DecodeString(v.MessageKeyConversationKeyHex)
	if err != nil {
		t.Fatalf("decode message_key_conversation_key_hex: %v", err)
	}
	keys := map[string][]byte{v.MessageKeyConversationKeyVersion: key}
	for _, media := range []struct{ hashKey, encryptedB64, plaintextB64 string }{
		{v.MediaFirstHashKey, v.MediaFirstEncryptedB64, v.MediaFirstPlaintextB64},
		{v.MediaSecondHashKey, v.MediaSecondEncryptedB64, v.MediaSecondPlaintextB64},
	} {
		encrypted, err := base64.StdEncoding.DecodeString(media.encryptedB64)
		if err != nil {
			t.Fatalf("decode %s: %v", media.hashKey, err)
		}
		want, err := base64.StdEncoding.DecodeString(media.plaintextB64)
		if err != nil {
			t.Fatalf("decode %s: %v", media.hashKey, err)
		}
		got, err := core.DecryptMedia(encrypted, v.EventMessageKeyB64, keys, media.hashKey)
		if err != nil {
			t.Fatalf("DecryptMedia %s: %v", media.hashKey, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s did not decrypt to the original bytes", media.hashKey)
		}
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
