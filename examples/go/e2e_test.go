package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xdevplatform/chat-xdk/go/chatxdk"
)

// TestE2ELive drives the example's real ChatCore + XChatClient against the live
// X Chat API. It is skipped unless CHATXDK_E2E=1 and the credentials env vars
// are set, so the normal offline `go test` is unaffected.
//
//	CHATXDK_E2E=1 X_ACCESS_TOKEN=... CHAT_PRIVATE_KEYS_B64=... CHAT_SIGNING_KEY_VERSION=... \
//	CHAT_CONVERSATION_ID=... go test -run TestE2ELive -v
//
// Flow (each numbered step asserts against the live API):
//  1. batch-decrypt inbound history (pagination when a second page exists)
//  2. rotate the conversation key (prepare -> POST /keys -> decrypt own CKCE)
//  3. send a threaded reply with an entity + TTL under the rotated key,
//     fetch it back, decrypt it via the single-event path, and verify it
//  4. react to the sent message (add + remove), decrypting the add back
//
// Optional extras:
//
//	CHATXDK_E2E_MEDIA=1   also stream-encrypts a media blob, uploads it,
//	                      sends a message referencing it, then downloads and
//	                      stream-decrypts it back to the original bytes
//	CHATXDK_E2E_GROUPS=1  also creates a group (two-signature create), sends a
//	                      group message, and adds the 1:1 partner as a member
func TestE2ELive(t *testing.T) {
	if os.Getenv("CHATXDK_E2E") != "1" {
		t.Skip("set CHATXDK_E2E=1 to run the live e2e test")
	}
	token := os.Getenv("X_ACCESS_TOKEN")
	blob := os.Getenv("CHAT_PRIVATE_KEYS_B64")
	ver := os.Getenv("CHAT_SIGNING_KEY_VERSION")
	conv := os.Getenv("CHAT_CONVERSATION_ID")
	if token == "" || blob == "" || ver == "" || conv == "" {
		t.Fatal("missing X_ACCESS_TOKEN / CHAT_PRIVATE_KEYS_B64 / CHAT_SIGNING_KEY_VERSION / CHAT_CONVERSATION_ID")
	}

	api := NewXChatClient(token, "https://api.x.com")
	core := NewChatCore()
	defer core.Close()
	if err := core.LoadKeys(blob, ver); err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}
	myID, err := api.GetMyUserID()
	if err != nil {
		t.Fatalf("GetMyUserID: %v", err)
	}
	// Session identity: every encrypt/prepare call below signs as this user.
	if err := core.SetIdentity(myID); err != nil {
		t.Fatalf("SetIdentity: %v", err)
	}

	// -- 1. Inbound history: batch decrypt (+ pagination when available) ----
	raw, keyEventsPage1, next, err := api.GetEvents(conv, 10, "")
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if next != "" {
		raw2, keyEventsPage2, _, err := api.GetEvents(conv, 10, next)
		if err != nil {
			t.Fatalf("GetEvents page 2: %v", err)
		}
		keyEventsPage1 = append(keyEventsPage1, keyEventsPage2...)
		ids1 := map[string]bool{}
		for _, e := range raw {
			ids1[e.ID] = true
		}
		overlap := false
		for _, e := range raw2 {
			if ids1[e.ID] {
				overlap = true
			}
		}
		if len(raw2) == 0 || overlap {
			t.Fatal("pagination made no progress")
		}
		raw = append(raw, raw2...)
		t.Logf("pagination: fetched second page with %d events", len(raw2))
	}

	// Build signing keys for every sender plus self (for verification), and
	// keep each user's raw public-keys rows for the prepare calls below.
	seen := map[string]bool{myID: true}
	ids := []string{myID}
	for _, e := range raw {
		if e.SenderID != "" && !seen[e.SenderID] {
			seen[e.SenderID] = true
			ids = append(ids, e.SenderID)
		}
	}
	var signing []chatxdk.SigningKeyEntry
	pksByUser := map[string][]map[string]any{}
	for _, id := range ids {
		pks, err := api.GetPublicKeys(id)
		if err != nil {
			continue
		}
		pksByUser[id] = pks
		for _, pk := range pks {
			signing = append(signing, chatxdk.SigningKeyEntry{
				UserID:                     id,
				PublicKeyVersion:           str(pk["public_key_version"]),
				PublicKey:                  str(pk["signing_public_key"]),
				IdentityPublicKey:          str(pk["public_key"]),
				IdentityPublicKeySignature: str(pk["identity_public_key_signature"]),
			})
		}
	}
	// Store the signing keys once; every decrypt call below passes nil and
	// verifies against this set.
	if err := core.SetSigningKeys(signing); err != nil {
		t.Fatalf("SetSigningKeys: %v", err)
	}

	// The KeyChange events from meta.conversation_key_events carry the
	// conversation keys; they must be in the same batch as the messages.
	eventsB64 := append([]string{}, keyEventsPage1...)
	for _, e := range raw {
		if e.EncodedEvent != "" {
			eventsB64 = append(eventsB64, e.EncodedEvent)
		}
	}
	batch, err := core.DecryptBatch(eventsB64, nil)
	if err != nil {
		t.Fatalf("DecryptBatch: %v", err)
	}
	decrypted := 0
	for _, m := range batch.Messages {
		if MessageText(&m.Event) != "" {
			decrypted++
		}
	}
	t.Logf("live inbound messages decrypted: %d; conversation keys: %d", decrypted, len(batch.ConversationKeys.Keys))
	if decrypted == 0 {
		t.Fatal("expected to decrypt at least one live inbound message")
	}

	// Canonical conversation_id + partner id + the raw envelope of the last
	// inbound message (the reply anchor) + the raw key-change events (so the
	// reply preview can decrypt an original sent under an older key).
	canonicalConv := conv
	lastInboundEvent := ""
	var ckces []string
	for _, m := range batch.Messages {
		var meta chatxdk.EventMeta
		_ = json.Unmarshal(m.Event.Raw(), &meta)
		if meta.ConversationID != nil && *meta.ConversationID != "" {
			canonicalConv = *meta.ConversationID
		}
		if m.Event.Type == "KeyChange" && m.OriginalB64 != "" {
			ckces = append(ckces, m.OriginalB64)
		}
		if m.Event.Type == "Message" && meta.SenderID != nil && *meta.SenderID != myID &&
			m.OriginalB64 != "" {
			lastInboundEvent = m.OriginalB64
		}
	}
	partnerID := ""
	for _, id := range ids {
		if id != myID {
			partnerID = id
			break
		}
	}
	if partnerID == "" {
		t.Fatal("expected a conversation partner among the senders")
	}

	// -- 2. Key rotation: prepare -> POST /keys -> decrypt own CKCE ---------
	bothKeys := append(keyEntries(pksByUser[myID], myID), keyEntries(pksByUser[partnerID], partnerID)...)
	prep, err := core.PrepareConversationKeyChange(bothKeys, "")
	if err != nil {
		t.Fatalf("PrepareConversationKeyChange: %v", err)
	}
	pub, err := core.PublicKeys()
	if err != nil {
		t.Fatalf("PublicKeys: %v", err)
	}
	resp, err := api.AddConversationKeys(conv, PrepToRequest(prep, pub.Signing))
	if err != nil {
		t.Fatalf("AddConversationKeys: %v", err)
	}
	data, _ := resp["data"].(map[string]any)
	if !truthy(data["sequence_id"]) && !truthy(data["conversation_key_change_sequence_id"]) {
		t.Fatalf("key rotation not acknowledged: %v", resp)
	}
	logMsg := fmt.Sprintf("rotated conversation key to version %s", prep.ConversationKeyVersion)
	if str(data["conversation_id"]) != "" {
		logMsg += "; server conversation_id: " + str(data["conversation_id"])
	}
	t.Log(logMsg)

	// The rotated key becomes the sending key; re-fetch (polling briefly, in
	// case the CKCE has not propagated yet) so our own CKCE decrypts and the
	// SDK cache includes the new version.
	kv := prep.ConversationKeyVersion
	var convKeys map[string][]byte
	for attempt := 0; attempt < 5; attempt++ {
		var pageKeyEvents []string
		raw, pageKeyEvents, _, err = api.GetEvents(conv, 10, "")
		if err != nil {
			t.Fatalf("GetEvents: %v", err)
		}
		eventsB64 = append(eventsB64[:0], pageKeyEvents...)
		for _, e := range raw {
			if e.EncodedEvent != "" {
				eventsB64 = append(eventsB64, e.EncodedEvent)
			}
		}
		batch, err = core.DecryptBatch(eventsB64, nil)
		if err != nil {
			t.Fatalf("DecryptBatch: %v", err)
		}
		convKeys = batch.ConversationKeys.Keys
		if _, ok := convKeys[kv]; ok {
			break
		}
		time.Sleep(1500 * time.Millisecond)
	}
	key, ok := convKeys[kv]
	if !ok {
		t.Fatalf("own rotated CKCE (version %s) did not decrypt+verify", kv)
	}
	for _, m := range batch.Messages {
		if m.Event.Type == "KeyChange" && m.OriginalB64 != "" {
			ckces = append(ckces, m.OriginalB64)
		}
	}

	// -- 3. Send under the rotated key; fetch back; single-event decrypt ----
	// The reply anchors on the raw inbound event; the CKCEs let the SDK
	// decrypt an original sent under an older key than this reply's.
	marker := fmt.Sprintf("chat-xdk e2e [go] %d", time.Now().Unix())
	body, err := core.EncryptReply(canonicalConv, "@user "+marker, &ReplyOptions{
		ReplyToEvent:           lastInboundEvent,
		ReplyToCkces:           ckces,
		ConversationKey:        key,
		ConversationKeyVersion: kv,
		Entities:               []chatxdk.EntityTuple{chatxdk.NewEntity(0, 5, "mention")},
		TTLMsec:                24 * 60 * 60 * 1000,
	})
	if err != nil {
		t.Fatalf("EncryptReply: %v", err)
	}
	if err := api.SendMessage(canonicalConv, body); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	t.Logf("sent live encrypted message: %q", marker)

	one, sentEvent := awaitDecrypted(t, api, core, conv, convKeys, body.MessageID)
	if got := one.Text(); got != "@user "+marker {
		t.Fatalf("round-trip text mismatch: got %q", got)
	}
	if !one.Verified {
		t.Fatal("own sent message failed signature verification")
	}
	if sentEvent == "" {
		t.Fatal("sent message has no raw envelope to react to")
	}
	t.Log("sent message decrypted + verified via the single-event path")

	// -- 4. Reactions: add (round-trip) then remove --------------------------
	// The reaction targets the raw sent event; conversation id and target
	// sequence id derive from it.
	add, err := core.EncryptAddReaction(sentEvent, "\U0001f44d", key, kv)
	if err != nil {
		t.Fatalf("EncryptAddReaction: %v", err)
	}
	if err := api.SendMessage(canonicalConv, add); err != nil {
		t.Fatalf("SendMessage (reaction add): %v", err)
	}
	reaction, _ := awaitDecrypted(t, api, core, conv, convKeys, add.MessageID)
	if reaction.Content.ContentType != "Reaction" || reaction.Content.ReactionContent == nil ||
		reaction.Content.ReactionContent.Emoji != "\U0001f44d" {
		t.Fatalf("expected a Reaction event, got %+v", reaction.Content)
	}
	if !reaction.Verified {
		t.Fatal("reaction failed signature verification")
	}
	t.Log("reaction add decrypted + verified")

	remove, err := core.EncryptRemoveReaction(sentEvent, "\U0001f44d", key, kv)
	if err != nil {
		t.Fatalf("EncryptRemoveReaction: %v", err)
	}
	if err := api.SendMessage(canonicalConv, remove); err != nil {
		t.Fatalf("SendMessage (reaction remove): %v", err)
	}
	t.Log("reaction remove sent")

	// -- 5. Optional: media — stream-encrypt, upload, send, download, decrypt
	if os.Getenv("CHATXDK_E2E_MEDIA") == "1" {
		// A deterministic multi-chunk payload, so the incremental encryptor
		// emits several frames and any corruption is byte-attributable.
		plaintext := make([]byte, 300_000)
		for i := range plaintext {
			plaintext[i] = byte((i*31 + 7) % 256)
		}
		ciphertext, err := core.EncryptMedia(plaintext, key)
		if err != nil {
			t.Fatalf("EncryptMedia: %v", err)
		}
		mediaHashKey, err := api.UploadMedia(canonicalConv, ciphertext)
		if err != nil {
			t.Fatalf("UploadMedia: %v", err)
		}
		t.Logf("encrypted media uploaded: %s (%d bytes)", mediaHashKey, len(ciphertext))

		mediaText := fmt.Sprintf("chat-xdk e2e media [go] %d", time.Now().Unix())
		mediaType := int32(5)
		mediaBody, err := core.EncryptReply(canonicalConv, mediaText, &ReplyOptions{
			ConversationKey:        key,
			ConversationKeyVersion: kv,
			Attachments: []chatxdk.AttachmentDescriptor{{
				AttachmentType: "media",
				MediaHashKey:   mediaHashKey,
				Width:          0,
				Height:         0,
				FilesizeBytes:  int64(len(plaintext)),
				Filename:       "e2e.bin",
				MediaType:      &mediaType,
			}},
			TTLMsec: 24 * 60 * 60 * 1000,
		})
		if err != nil {
			t.Fatalf("EncryptReply (media): %v", err)
		}
		if err := api.SendMessage(canonicalConv, mediaBody); err != nil {
			t.Fatalf("SendMessage (media): %v", err)
		}
		mediaOne, _ := awaitDecrypted(t, api, core, conv, convKeys, mediaBody.MessageID)
		if !mediaOne.Verified {
			t.Fatal("media message failed signature verification")
		}
		if gotKey := attachmentMediaHashKey(mediaOne); gotKey != mediaHashKey {
			t.Fatalf("attachment did not round-trip: got %q, want %q", gotKey, mediaHashKey)
		}

		downloaded, err := api.DownloadMedia(canonicalConv, mediaHashKey)
		if err != nil {
			t.Fatalf("DownloadMedia: %v", err)
		}
		decryptedMedia, err := core.DecryptMedia(downloaded, key)
		if err != nil {
			t.Fatalf("DecryptMedia: %v", err)
		}
		if !bytes.Equal(decryptedMedia, plaintext) {
			t.Fatal("downloaded media did not decrypt to the original bytes")
		}
		t.Log("media downloaded + stream-decrypted to the original bytes")
	}

	// -- 6. Optional: group create + message + member add --------------------
	if os.Getenv("CHATXDK_E2E_GROUPS") == "1" {
		groupsFlow(t, api, core, myID, partnerID, bothKeys)
	}

	t.Log("E2E GO: PASS")
}

// groupsFlow creates a group (two-signature create), sends and verifies a
// group message under the fresh key, and adds the 1:1 partner as a member.
func groupsFlow(t *testing.T, api *XChatClient, core *ChatCore, myID, partnerID string, bothKeys []chatxdk.PublicKeyInput) {
	t.Helper()
	var myKeys []chatxdk.PublicKeyInput
	for _, k := range bothKeys {
		if k.UserID == myID {
			myKeys = append(myKeys, k)
		}
	}
	pub, err := core.PublicKeys()
	if err != nil {
		t.Fatalf("PublicKeys: %v", err)
	}
	signingPub := pub.Signing

	groupID, err := api.InitializeGroup()
	if err != nil {
		t.Fatalf("InitializeGroup: %v", err)
	}
	if !strings.HasPrefix(groupID, "g") {
		t.Fatalf("unexpected group id: %q", groupID)
	}

	// Create with the caller as sole member/admin so the member add below
	// exercises PrepareGroupMembersChange with the partner.
	prep, err := core.PrepareGroupCreate(myKeys, groupID, []string{myID}, []string{myID})
	if err != nil {
		t.Fatalf("PrepareGroupCreate: %v", err)
	}
	members := []string{myID}
	if _, err := api.CreateConversation(groupBody(groupID, members, myID, prep, signingPub)); err != nil {
		// Some deployments reject single-member groups; fall back to creating
		// with both participants (skipping the member-add below).
		prep, err = core.PrepareGroupCreate(bothKeys, groupID, []string{myID, partnerID}, []string{myID})
		if err != nil {
			t.Fatalf("PrepareGroupCreate (fallback): %v", err)
		}
		members = []string{myID, partnerID}
		if _, err := api.CreateConversation(groupBody(groupID, members, myID, prep, signingPub)); err != nil {
			t.Fatalf("CreateConversation: %v", err)
		}
	}
	kv := prep.ConversationKeyVersion
	key := prep.ConversationKey
	t.Logf("group created: %s with %d member(s)", groupID, len(members))

	// The fresh group key never arrived in a decrypted event, so it is not
	// in the SDK cache yet — pass it explicitly.
	marker := fmt.Sprintf("chat-xdk e2e group [go] %d", time.Now().Unix())
	msg, err := core.EncryptReply(groupID, marker, &ReplyOptions{
		ConversationKey:        key,
		ConversationKeyVersion: kv,
	})
	if err != nil {
		t.Fatalf("EncryptReply (group): %v", err)
	}
	if err := api.SendMessage(groupID, msg); err != nil {
		t.Fatalf("SendMessage (group): %v", err)
	}
	one, _ := awaitDecrypted(t, api, core, groupID, map[string][]byte{kv: key}, msg.MessageID)
	if one.Text() != marker || !one.Verified {
		t.Fatalf("group message round-trip failed: %+v", one)
	}
	t.Log("group message decrypted + verified")

	partnerIsMember := false
	for _, m := range members {
		if m == partnerID {
			partnerIsMember = true
		}
	}
	if !partnerIsMember {
		mPrep, err := core.PrepareGroupMembersChange(bothKeys, groupID, []string{partnerID}, members, []string{myID})
		if err != nil {
			t.Fatalf("PrepareGroupMembersChange: %v", err)
		}
		mBody := PrepToRequest(mPrep, signingPub)
		mBody["user_ids"] = []string{partnerID}
		if _, err := api.AddGroupMembers(groupID, mBody); err != nil {
			t.Fatalf("AddGroupMembers: %v", err)
		}
		t.Logf("group member add: %s added (key rotated to %s)", partnerID, mPrep.ConversationKeyVersion)
	}
}

// groupBody assembles the group-create request: roster fields plus the
// two-signature key change from PrepareGroupCreate.
func groupBody(groupID string, members []string, adminID string, prep *chatxdk.PreparedConversationChange, signingPub string) map[string]any {
	body := PrepToRequest(prep, signingPub)
	body["conversation_id"] = groupID
	body["group_members"] = members
	body["group_admins"] = []string{adminID}
	body["group_name"] = "chat-xdk e2e"
	return body
}

// keyEntries converts public-keys response rows into the flat entries the
// prepare methods take.
func keyEntries(pks []map[string]any, userID string) []chatxdk.PublicKeyInput {
	entries := make([]chatxdk.PublicKeyInput, 0, len(pks))
	for _, pk := range pks {
		version := str(pk["public_key_version"])
		entries = append(entries, chatxdk.PublicKeyInput{
			UserID:     userID,
			PublicKey:  str(pk["public_key"]),
			KeyVersion: version,
		})
	}
	return entries
}

// awaitDecrypted polls the conversation until the event for messageID lands,
// and returns it decrypted via the single-event path (DecryptOne, verifying
// against the stored signing keys) together with its raw base64 envelope
// (the anchor for reactions and replies).
//
// The target envelope is matched by its raw event id before decrypting, so a
// decrypt failure on our own event (e.g. a broken sign->verify loop) surfaces
// in the timeout message instead of being silently swallowed.
func awaitDecrypted(t *testing.T, api *XChatClient, core *ChatCore, conversationID string, convKeys map[string][]byte, messageID string) (*chatxdk.Message, string) {
	t.Helper()
	var lastErr error
	for try := 0; try < 10; try++ {
		events, _, _, err := api.GetEvents(conversationID, 25, "")
		if err != nil {
			t.Fatalf("GetEvents: %v", err)
		}
		for _, e := range events {
			if e.EncodedEvent == "" {
				continue
			}
			isTarget := e.ID == messageID
			one, err := core.DecryptOne(e.EncodedEvent, convKeys, nil)
			if err != nil {
				if isTarget {
					lastErr = err
				}
				continue
			}
			msg := one.AsMessage()
			if msg == nil {
				continue
			}
			if !isTarget && (msg.ID == nil || *msg.ID != messageID) {
				continue
			}
			return msg, e.EncodedEvent
		}
		time.Sleep(time.Second)
	}
	if lastErr != nil {
		t.Fatalf("event for sent message %q never appeared (last decrypt error: %v)", messageID, lastErr)
	}
	t.Fatalf("event for sent message %q never appeared", messageID)
	return nil, ""
}

// attachmentMediaHashKey returns the media hash key of the first media
// attachment in a decrypted message's content, or "".
func attachmentMediaHashKey(msg *chatxdk.Message) string {
	if msg.Content.TextContent == nil {
		return ""
	}
	var atts []struct {
		Media *struct {
			MediaHashKey string `json:"media_hash_key"`
		} `json:"media"`
	}
	if err := json.Unmarshal(msg.Content.TextContent.Attachments, &atts); err != nil {
		return ""
	}
	for _, a := range atts {
		if a.Media != nil {
			return a.Media.MediaHashKey
		}
	}
	return ""
}

// truthy reports whether a decoded JSON value is present and non-empty.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	default:
		return true
	}
}
