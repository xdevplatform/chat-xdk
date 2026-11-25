package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

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
		{UserID: "910002", IdentityPublicKey: v.IdentityPublicB64, PublicKeyVersion: "1"},
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
	result, err := core.DecryptBatch([]string{})
	if err != nil {
		t.Fatalf("DecryptBatch: %v", err)
	}
	if len(result.Events) != 0 {
		t.Errorf("expected no messages, got %d", len(result.Events))
	}
}

func TestDecryptOneRejectsGarbage(t *testing.T) {
	core, _ := loadedCore(t)
	defer core.Close()
	if _, err := core.DecryptOne("not-valid-base64!!!", map[string][]byte{}); err == nil {
		t.Error("expected error for invalid base64 event")
	}
}

// fixtureKeys returns the flat public-key entries the prepare methods take,
// built from the fixture identity key.
func fixtureKeys(v vectors) []chatxdk.PublicKeyInput {
	return []chatxdk.PublicKeyInput{
		{UserID: "1000", IdentityPublicKey: v.IdentityPublicB64, PublicKeyVersion: "1"},
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
	prep, err := core.PrepareGroupMembersRemove(fixtureKeys(v), "g123", []string{"2000"}, nil)
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
	size, err := chatxdk.EncryptedFileSize(uint64(len(plaintext)))
	if err != nil {
		t.Fatalf("EncryptedFileSize: %v", err)
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
			FilesizeBytes:  int64(size),
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

// attachmentIDs returns the attachment_id of each attachment of a decrypted
// message, empty for one that carries none.
func attachmentIDs(t *testing.T, event *chatxdk.Event) []string {
	t.Helper()
	msg := event.AsMessage()
	if msg == nil {
		t.Fatalf("expected a message, got %+v", event)
	}
	ids := make([]string, len(msg.Attachments))
	for i, raw := range msg.Attachments {
		var attachment struct {
			AttachmentID string `json:"attachment_id"`
		}
		if err := json.Unmarshal(raw, &attachment); err != nil {
			t.Fatalf("attachment %d: %v", i, err)
		}
		ids[i] = attachment.AttachmentID
	}
	return ids
}

// TestReplyAndReactionTargetOneAttachment replies and reacts to one photo of
// an album. Attachments carry ids in v1 sends: the chat reads its feature
// switches from CHAT_XDK_API_BASE_URL, here a local server that turns v1 on
// as the X API would.
func TestReplyAndReactionTargetOneAttachment(t *testing.T) {
	features := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"features":{"v1_send":true}}`))
	}))
	defer features.Close()
	t.Setenv("CHAT_XDK_API_BASE_URL", features.URL+"/")

	core, v := loadedCore(t)
	defer core.Close()
	core.FetchPublicKeysWith(func(userID string) ([]chatxdk.PublicKeyRecord, error) {
		if userID != v.EventSenderID {
			return nil, errors.New("no public keys for user " + userID)
		}
		return []chatxdk.PublicKeyRecord{{
			PublicKeyVersion:           v.EventSigningKeyVersion,
			PublicKey:                  v.IdentityPublicB64,
			SigningPublicKey:           v.SigningPublicB64,
			IdentityPublicKeySignature: v.IdentityPublicKeySignatureB64,
		}}, nil
	})
	// The key change brings the sender's public keys and the conversation key.
	if result, err := core.DecryptBatch([]string{v.EventKeyChangeB64}); err != nil || len(result.Errors) != 0 {
		t.Fatalf("DecryptBatch: %v %v", err, result)
	}
	key := v.conversationKey(t)
	keys := map[string][]byte{v.EventConversationKeyVersion: key}
	mediaType := int32(1)
	photo := func(mediaHashKey string) chatxdk.AttachmentDescriptor {
		return chatxdk.AttachmentDescriptor{
			AttachmentType: "media",
			MediaHashKey:   mediaHashKey,
			Width:          4,
			Height:         3,
			FilesizeBytes:  1024,
			Filename:       mediaHashKey + ".jpg",
			MediaType:      &mediaType,
		}
	}

	// The switches arrive in the background: send until the album is v1.
	var album string
	var ids []string
	deadline := time.Now().Add(10 * time.Second)
	for {
		body, err := core.EncryptReply(v.EventConversationID, "two photos", &ReplyOptions{
			ConversationKey:        key,
			ConversationKeyVersion: v.EventConversationKeyVersion,
			Attachments:            []chatxdk.AttachmentDescriptor{photo("photo-1"), photo("photo-2")},
		})
		if err != nil {
			t.Fatalf("EncryptReply (album): %v", err)
		}
		album = deliveredEvent(t, body.EventB64, "2100000000000000001")
		event, err := core.DecryptOne(album, keys)
		if err != nil {
			t.Fatalf("DecryptOne (album): %v", err)
		}
		ids = attachmentIDs(t, event)
		if len(ids) == 2 && ids[0] != "" && ids[1] != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the chat never turned v1 on: attachment ids %q", ids)
		}
		time.Sleep(50 * time.Millisecond)
	}
	second := ids[1]

	reply, err := core.EncryptReply(v.EventConversationID, "the second one", &ReplyOptions{
		ReplyToEvent:        album,
		ReplyToAttachmentID: second,
	})
	if err != nil {
		t.Fatalf("EncryptReply (to one attachment): %v", err)
	}
	event, err := core.DecryptOne(deliveredEvent(t, reply.EventB64, "2100000000000000002"), keys)
	if err != nil {
		t.Fatalf("DecryptOne (reply): %v", err)
	}
	msg := event.AsMessage()
	if msg == nil || msg.Content.TextContent == nil {
		t.Fatalf("expected a reply, got %+v", event)
	}
	var preview struct {
		ReplyingToAttachmentID string `json:"replying_to_attachment_id"`
	}
	if err := json.Unmarshal(msg.Content.TextContent.ReplyingToPreview, &preview); err != nil {
		t.Fatalf("replying_to_preview: %v", err)
	}
	if preview.ReplyingToAttachmentID != second {
		t.Errorf("reply preview names attachment %q, want %q", preview.ReplyingToAttachmentID, second)
	}

	for _, c := range []struct {
		encrypt     func(string, string, string, []byte, string) (*SendBody, error)
		contentType string
		sequenceID  string
	}{
		{core.EncryptAddReactionToAttachment, "Reaction", "2100000000000000003"},
		{core.EncryptRemoveReactionToAttachment, "ReactionRemoved", "2100000000000000004"},
	} {
		body, err := c.encrypt(album, second, "\U0001f44d", key, v.EventConversationKeyVersion)
		if err != nil {
			t.Fatalf("%s: %v", c.contentType, err)
		}
		event, err := core.DecryptOne(deliveredEvent(t, body.EventB64, c.sequenceID), keys)
		if err != nil {
			t.Fatalf("DecryptOne (%s): %v", c.contentType, err)
		}
		msg := event.AsMessage()
		if msg == nil || msg.Content.ContentType != c.contentType || msg.Content.ReactionContent == nil {
			t.Fatalf("expected a %s, got %+v", c.contentType, event)
		}
		if got := msg.Content.ReactionContent.TargetAttachmentID; got != second {
			t.Errorf("%s names attachment %q, want %q", c.contentType, got, second)
		}
	}
}

// TestCachedKeyReplyFlow is the bot's send path end to end, offline: the SDK
// fetches the fixture sender's public keys, they verify the fixture key
// change, the batch decrypt adopts its key into the SDK cache, and the
// reply-by-event needs neither a sender nor a conversation key argument.
func TestCachedKeyReplyFlow(t *testing.T) {
	core, v := loadedCore(t)
	defer core.Close()
	core.FetchPublicKeysWith(func(userID string) ([]chatxdk.PublicKeyRecord, error) {
		if userID != v.EventSenderID {
			return nil, errors.New("no public keys for user " + userID)
		}
		return []chatxdk.PublicKeyRecord{{
			PublicKeyVersion:           v.EventSigningKeyVersion,
			PublicKey:                  v.IdentityPublicB64,
			SigningPublicKey:           v.SigningPublicB64,
			IdentityPublicKeySignature: v.IdentityPublicKeySignatureB64,
		}}, nil
	})

	result, err := core.DecryptBatch([]string{v.EventKeyChangeB64, v.EventMessageB64})
	if err != nil {
		t.Fatalf("DecryptBatch: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected decrypt errors: %v", result.Errors)
	}
	if len(result.MissingSigningKeys) != 0 || len(result.UnverifiedKeyChanges) != 0 {
		t.Fatalf("unverified events: missing %v, key changes %v", result.MissingSigningKeys, result.UnverifiedKeyChanges)
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

// thriftString is a Thrift string field: its id, then the value's length and
// bytes.
func thriftString(id uint16, value string) []byte {
	field := binary.BigEndian.AppendUint16([]byte{11}, id)
	field = binary.BigEndian.AppendUint32(field, uint32(len(value)))
	return append(field, value...)
}

// deliveredEvent is eventB64 as delivered: with the sequence id the server
// assigns, prepended as Thrift string field 1.
func deliveredEvent(t *testing.T, eventB64, sequenceID string) string {
	t.Helper()
	event, err := base64.StdEncoding.DecodeString(eventB64)
	if err != nil {
		t.Fatalf("decode event: %v", err)
	}
	return base64.StdEncoding.EncodeToString(append(thriftString(1, sequenceID), event...))
}

// deliveredAction is a signed action as delivered: the event the server
// relays for action, an entry of a prepared change's ActionSignatures, from
// senderID in conversationID, with the sequence id the server assigns.
func deliveredAction(t *testing.T, action chatxdk.ActionSignature, senderID, conversationID, sequenceID string) string {
	t.Helper()
	detail, err := base64.StdEncoding.DecodeString(action.EncodedMessageEventDetail)
	if err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	signed := action.MessageEventSignature
	var event []byte
	event = append(event, thriftString(1, sequenceID)...)
	event = append(event, thriftString(2, action.MessageID)...)
	event = append(event, thriftString(3, senderID)...)
	event = append(event, thriftString(4, conversationID)...)
	event = append(event, 12, 0, 7)
	event = append(event, detail...)
	event = append(event, 12, 0, 9)
	event = append(event, thriftString(1, signed.Signature)...)
	event = append(event, thriftString(2, signed.PublicKeyVersion)...)
	event = append(event, thriftString(3, signed.SignatureVersion)...)
	event = append(event, 0, 0)
	return base64.StdEncoding.EncodeToString(event)
}

// party is a core with fresh keys as a user, and the keys others hold for it.
type party struct {
	core   *ChatCore
	userID string
	// privateKeysB64 is the user's private-key blob, registered under key
	// version "1": what signs the user in to another chat.
	privateKeysB64 string
	// record is the record the X API returns for the user's public keys.
	record    chatxdk.PublicKeyRecord
	publicKey chatxdk.PublicKeyInput
}

func newParty(t *testing.T, userID string) *party {
	t.Helper()
	core := NewChatCore()
	t.Cleanup(core.Close)
	payload, privateKeysB64, err := core.GenerateAndRegister()
	if err != nil {
		t.Fatalf("GenerateAndRegister: %v", err)
	}
	if err := core.LoadKeys(privateKeysB64, "1"); err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}
	if err := core.SetIdentity(userID); err != nil {
		t.Fatalf("SetIdentity: %v", err)
	}
	registration := payload.PublicKey
	return &party{
		core:           core,
		userID:         userID,
		privateKeysB64: privateKeysB64,
		record: chatxdk.PublicKeyRecord{
			PublicKeyVersion:           "1",
			PublicKey:                  registration.PublicKey,
			SigningPublicKey:           registration.SigningPublicKey,
			IdentityPublicKeySignature: registration.IdentityPublicKeySignature,
		},
		publicKey: chatxdk.PublicKeyInput{
			UserID:            userID,
			IdentityPublicKey: registration.PublicKey,
			PublicKeyVersion:  "1",
		},
	}
}

// testGroup is the group the tests' key changes and messages belong to.
const testGroup = "g900"

// publicKeyDirectory stands in for the X API's public keys: each user's
// records by user id, and the users whose keys were asked for, in order.
type publicKeyDirectory struct {
	records map[string][]chatxdk.PublicKeyRecord

	mu    sync.Mutex
	asked []string
}

func directoryOf(parties ...*party) *publicKeyDirectory {
	records := make(map[string][]chatxdk.PublicKeyRecord, len(parties))
	for _, p := range parties {
		records[p.userID] = []chatxdk.PublicKeyRecord{p.record}
	}
	return &publicKeyDirectory{records: records}
}

// fetch is a lookup ChatCore.FetchPublicKeysWith takes. It fails for a user
// the directory does not hold.
func (d *publicKeyDirectory) fetch(userID string) ([]chatxdk.PublicKeyRecord, error) {
	d.mu.Lock()
	d.asked = append(d.asked, userID)
	d.mu.Unlock()
	records, ok := d.records[userID]
	if !ok {
		return nil, errors.New("no public keys for user " + userID)
	}
	return records, nil
}

// askedFor is the users whose keys were asked for so far, in order.
func (d *publicKeyDirectory) askedFor() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string{}, d.asked...)
}

// keyChangeAndMessage is the page keyChangeAndMessageIn builds for testGroup.
func keyChangeAndMessage(t *testing.T, admin *party, members []*party, author *party, text string) (keyChange, message string) {
	t.Helper()
	return keyChangeAndMessageIn(t, testGroup, admin, members, author, text)
}

// keyChangeAndMessageIn is the page that follows a key rotation of the group
// conversationID: the key change admin made for members, which admin signed,
// and the message author then sent under the new key, both as delivered.
func keyChangeAndMessageIn(t *testing.T, conversationID string, admin *party, members []*party, author *party, text string) (keyChange, message string) {
	t.Helper()
	publicKeys := make([]chatxdk.PublicKeyInput, 0, len(members))
	for _, member := range members {
		publicKeys = append(publicKeys, member.publicKey)
	}
	prepared, err := admin.core.PrepareConversationKeyChange(publicKeys, conversationID)
	if err != nil {
		t.Fatalf("PrepareConversationKeyChange: %v", err)
	}
	keyChange = deliveredAction(t, prepared.ActionSignatures[0], admin.userID, conversationID, "2100000000000000000")
	body, err := author.core.EncryptReply(conversationID, text, &ReplyOptions{
		ConversationKey:        prepared.ConversationKey,
		ConversationKeyVersion: prepared.ConversationKeyVersion,
	})
	if err != nil {
		t.Fatalf("EncryptReply: %v", err)
	}
	return keyChange, deliveredEvent(t, body.EventB64, "2100000000000000001")
}

// messageTexts is the text of each event a batch decrypted; "" for an event
// that is not a text message.
func messageTexts(result *chatxdk.DecryptEventsResult) []string {
	texts := make([]string, len(result.Events))
	for i := range result.Events {
		texts[i] = MessageText(&result.Events[i].Event)
	}
	return texts
}

// recipientsOf is the users a prepared change encrypts its key to, sorted.
func recipientsOf(prepared *chatxdk.PreparedConversationChange) []string {
	userIDs := make([]string, len(prepared.ConversationParticipantKeys))
	for i, key := range prepared.ConversationParticipantKeys {
		userIDs[i] = key.UserID
	}
	sort.Strings(userIDs)
	return userIDs
}

func TestDecryptBatchFetchesTheKeysOfTheMemberWhoMadeAKeyChange(t *testing.T) {
	// An admin rotates a group's key and a member sends a message under it:
	// the admin signed the key change and sent no message on the page.
	admin, member, bot := newParty(t, "5001"), newParty(t, "5002"), newParty(t, "5003")
	keyChange, message := keyChangeAndMessage(t, admin, []*party{admin, member, bot}, member, "hello group")
	events := []string{keyChange, message}

	// With nothing to fetch public keys with, the result names the signing
	// key each event lacked. The key change does not verify: its key is
	// dropped and the message does not decrypt.
	unverified, err := bot.core.DecryptBatch(events)
	if err != nil {
		t.Fatalf("DecryptBatch: %v", err)
	}
	if len(unverified.Events) != 0 {
		t.Errorf("expected no decrypted events, got %d", len(unverified.Events))
	}
	wantMissing := map[string]chatxdk.MissingSigningKey{
		"0": {UserID: "5001", PublicKeyVersion: "1"},
		"1": {UserID: "5002", PublicKeyVersion: "1"},
	}
	if !reflect.DeepEqual(unverified.MissingSigningKeys, wantMissing) {
		t.Errorf("missing signing keys %v, want %v", unverified.MissingSigningKeys, wantMissing)
	}

	// The SDK fetches the keys of both senders, the admin's as well, and
	// decrypts the page with them.
	directory := directoryOf(admin, member)
	bot.core.FetchPublicKeysWith(directory.fetch)
	result, err := bot.core.DecryptBatch(events)
	if err != nil {
		t.Fatalf("DecryptBatch: %v", err)
	}
	if asked := directory.askedFor(); !reflect.DeepEqual(asked, []string{"5001", "5002"}) {
		t.Errorf("asked for the keys of %v, want [5001 5002]", asked)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected decrypt errors: %v", result.Errors)
	}
	if len(result.MissingSigningKeys) != 0 || len(result.UnverifiedKeyChanges) != 0 {
		t.Errorf("unverified events: missing %v, key changes %v", result.MissingSigningKeys, result.UnverifiedKeyChanges)
	}
	if texts := messageTexts(result); !reflect.DeepEqual(texts, []string{"", "hello group"}) {
		t.Fatalf("expected the key change and the message, got %q", texts)
	}

	// The SDK stored the keys: the next page needs no fetch.
	if _, err := bot.core.DecryptBatch(events); err != nil {
		t.Fatalf("DecryptBatch: %v", err)
	}
	if asked := directory.askedFor(); len(asked) != 2 {
		t.Errorf("expected no further fetch, asked for the keys of %v", asked)
	}
}

func TestAFailedPublicKeyFetchLeavesTheOtherUsersKeysArriving(t *testing.T) {
	admin, member, bot := newParty(t, "5001"), newParty(t, "5002"), newParty(t, "5003")
	keyChange, message := keyChangeAndMessage(t, admin, []*party{admin, member, bot}, member, "hello group")
	events := []string{keyChange, message}

	// The directory holds the admin's keys alone: the member's fetch fails.
	directory := directoryOf(admin)
	bot.core.FetchPublicKeysWith(directory.fetch)
	result, err := bot.core.DecryptBatch(events)
	if err != nil {
		t.Fatalf("DecryptBatch: %v", err)
	}
	if asked := directory.askedFor(); !reflect.DeepEqual(asked, []string{"5001", "5002"}) {
		t.Errorf("asked for the keys of %v, want [5001 5002]", asked)
	}

	// The key change verifies with the admin's keys, and the result names
	// the key the member's message still lacks.
	if len(result.UnverifiedKeyChanges) != 0 {
		t.Errorf("unverified key changes: %v", result.UnverifiedKeyChanges)
	}
	if texts := messageTexts(result); !reflect.DeepEqual(texts, []string{""}) {
		t.Errorf("expected the key change alone, got %q", texts)
	}
	wantMissing := map[string]chatxdk.MissingSigningKey{
		"1": {UserID: "5002", PublicKeyVersion: "1"},
	}
	if !reflect.DeepEqual(result.MissingSigningKeys, wantMissing) {
		t.Errorf("missing signing keys %v, want %v", result.MissingSigningKeys, wantMissing)
	}

	// The SDK remembers the lookup that brought no key: the next page does
	// not repeat it.
	if _, err := bot.core.DecryptBatch(events); err != nil {
		t.Fatalf("DecryptBatch: %v", err)
	}
	if asked := directory.askedFor(); len(asked) != 2 {
		t.Errorf("expected no further fetch, asked for the keys of %v", asked)
	}
}

func TestPrepareCallsFetchThePublicKeysTheyAreNotPassed(t *testing.T) {
	admin, member := newParty(t, "5001"), newParty(t, "5002")
	directory := directoryOf(admin, member)
	admin.core.FetchPublicKeysWith(directory.fetch)

	// A one-to-one named by the other user's id: the SDK fetches the
	// identity keys of both users.
	direct, err := admin.core.PrepareConversationKeyChange(nil, "5002")
	if err != nil {
		t.Fatalf("PrepareConversationKeyChange: %v", err)
	}
	if direct.ConversationID != "5001:5002" {
		t.Errorf("conversation id %q, want 5001:5002", direct.ConversationID)
	}
	if recipients := recipientsOf(direct); !reflect.DeepEqual(recipients, []string{"5001", "5002"}) {
		t.Errorf("key change encrypted to %v, want [5001 5002]", recipients)
	}
	if asked := directory.askedFor(); !reflect.DeepEqual(asked, []string{"5001", "5002"}) {
		t.Errorf("asked for the keys of %v, want [5001 5002]", asked)
	}

	// The SDK stored the keys: the group calls, which name their members,
	// need no fetch.
	members := []string{"5001", "5002"}
	created, err := admin.core.PrepareGroupCreate(nil, testGroup, members, members[:1], "")
	if err != nil {
		t.Fatalf("PrepareGroupCreate: %v", err)
	}
	if recipients := recipientsOf(created); !reflect.DeepEqual(recipients, []string{"5001", "5002"}) {
		t.Errorf("group create encrypted to %v, want [5001 5002]", recipients)
	}
	removed, err := admin.core.PrepareGroupMembersRemove(nil, testGroup, members[1:], members[:1])
	if err != nil {
		t.Fatalf("PrepareGroupMembersRemove: %v", err)
	}
	if recipients := recipientsOf(removed); !reflect.DeepEqual(recipients, []string{"5001"}) {
		t.Errorf("member removal encrypted to %v, want [5001]", recipients)
	}
	if asked := directory.askedFor(); len(asked) != 2 {
		t.Errorf("expected no further fetch, asked for the keys of %v", asked)
	}
}

// sentMessage is one message posted to the fake X API: the path it was
// posted to and its body.
type sentMessage struct {
	path string
	body SendBody
}

// fakeXAPI is the X API as the bot sees it, offline: users' public keys, one
// page of events, and a record of the messages it was sent.
type fakeXAPI struct {
	directory *publicKeyDirectory
	// events is the data events of the page.
	events []EventItem
	// keyEvents is the key events of the page.
	keyEvents []string

	mu   sync.Mutex
	sent []sentMessage
}

func (api *fakeXAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/2/users/") && strings.HasSuffix(path, "/public_keys"):
		userID := strings.TrimSuffix(strings.TrimPrefix(path, "/2/users/"), "/public_keys")
		records, err := api.directory.fetch(userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		// The resource as the API returns it: the fields of a record, and
		// one the SDK does not read.
		data := make([]map[string]any, 0, len(records))
		for _, record := range records {
			data = append(data, map[string]any{
				"public_key_version":            record.PublicKeyVersion,
				"public_key":                    record.PublicKey,
				"signing_public_key":            record.SigningPublicKey,
				"identity_public_key_signature": record.IdentityPublicKeySignature,
				"juicebox_config":               map[string]any{},
			})
		}
		writeJSON(w, map[string]any{"data": data})
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/events"):
		writeJSON(w, map[string]any{
			"data": api.events,
			"meta": map[string]any{"conversation_key_events": api.keyEvents},
		})
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/messages"):
		var body SendBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		api.mu.Lock()
		api.sent = append(api.sent, sentMessage{path: path, body: body})
		api.mu.Unlock()
		writeJSON(w, map[string]any{})
	default:
		http.NotFound(w, r)
	}
}

// sentMessages is the messages posted so far, in order.
func (api *fakeXAPI) sentMessages() []sentMessage {
	api.mu.Lock()
	defer api.mu.Unlock()
	return append([]sentMessage{}, api.sent...)
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func TestBotRepliesToAMessageUnderAKeyChangeWhoseSignerSentNoMessage(t *testing.T) {
	admin, member, bot := newParty(t, "5001"), newParty(t, "5002"), newParty(t, "5003")
	keyChange, message := keyChangeAndMessage(t, admin, []*party{admin, member, bot}, member, "hello group")

	// The page as the X API returns it: the message in its data, the key
	// change apart, among its key events.
	api := &fakeXAPI{
		directory: directoryOf(admin, member, bot),
		events: []EventItem{{
			ID:             "2100000000000000001",
			ConversationID: testGroup,
			SenderID:       member.userID,
			EncodedEvent:   message,
		}},
		keyEvents: []string{keyChange},
	}
	server := httptest.NewServer(api)
	defer server.Close()
	chatbot := NewBot(bot.core, NewXChatClient("token", server.URL), bot.userID)
	if err := chatbot.PollOnce(testGroup); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}

	// The bot's SDK fetched the keys of the admin, who sent no message, and
	// of the member, and the bot answered the member's message.
	if asked := api.directory.askedFor(); !reflect.DeepEqual(asked, []string{"5001", "5002"}) {
		t.Errorf("asked for the keys of %v, want [5001 5002]", asked)
	}
	sent := api.sentMessages()
	if len(sent) != 1 {
		t.Fatalf("expected one reply, got %d", len(sent))
	}
	if want := "/2/chat/conversations/" + testGroup + "/messages"; sent[0].path != want {
		t.Errorf("reply posted to %q, want %q", sent[0].path, want)
	}
	reply := sent[0].body
	if reply.MessageID == "" || reply.EncodedMessageCreateEvent == "" || reply.EncodedMessageEventSignature == "" {
		t.Errorf("incomplete reply: %+v", reply)
	}

	// The page read again brings no second reply and no further fetch.
	if err := chatbot.PollOnce(testGroup); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if sent := api.sentMessages(); len(sent) != 1 {
		t.Errorf("expected one reply after the page is read again, got %d", len(sent))
	}
	if asked := api.directory.askedFor(); len(asked) != 2 {
		t.Errorf("expected no further fetch, asked for the keys of %v", asked)
	}
}
