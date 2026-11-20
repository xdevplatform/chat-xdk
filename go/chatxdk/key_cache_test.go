package chatxdk

import (
	"bytes"
	"errors"
	"strconv"
	"testing"
)

// The conversation-key cache and the signing-key store: what fills them and
// which calls read them.

// newSessionParty is a party whose chat has its user as session identity.
func newSessionParty(t *testing.T, userID string) *signerParty {
	t.Helper()
	party := newSignerParty(t, userID)
	if err := party.chat.SetIdentity(SetIdentityParams{UserID: userID, SigningKeyVersion: signerKeyVersion}); err != nil {
		t.Fatalf("SetIdentity failed: %v", err)
	}
	return party
}

// newCachingParty is a party with a session identity whose key cache is on.
func newCachingParty(t *testing.T, userID string) *signerParty {
	t.Helper()
	party := newSessionParty(t, userID)
	party.chat.SetCacheKeys(true)
	return party
}

// cachedSendVersion is the key version party encrypts under in the group
// when the call passes no key.
func cachedSendVersion(party *signerParty) (string, error) {
	payload, err := party.chat.EncryptMessage(EncryptMessageParams{ConversationID: signerGroup, Text: "hello"})
	if err != nil {
		return "", err
	}
	return payload.ConversationKeyVersion, nil
}

// assertSendsUnder checks that party, passing no key, encrypts under version.
func assertSendsUnder(t *testing.T, party *signerParty, version string) {
	t.Helper()
	got, err := cachedSendVersion(party)
	if err != nil {
		t.Fatalf("EncryptMessage with no key failed: %v", err)
	}
	if got != version {
		t.Errorf("encrypted under key version %q, want %q", got, version)
	}
}

// assertNoCachedKey checks that a send from party that passes no key fails
// because no key is cached.
func assertNoCachedKey(t *testing.T, party *signerParty) {
	t.Helper()
	_, err := cachedSendVersion(party)
	var chatErr *Error
	if !errors.As(err, &chatErr) || chatErr.Kind != ErrorKindInvalidState {
		t.Fatalf("expected an invalid-state error with no key cached, got %v", err)
	}
	assertContains(t, "error", chatErr.Message, "no cached conversation key for '"+signerGroup+"'")
}

// decryptKeyChange is change as party decrypts it on its own, with the
// signing keys of signers.
func decryptKeyChange(t *testing.T, party *signerParty, change signedKeyChange, signers ...*signerParty) *KeyChangeEvent {
	t.Helper()
	signingKeys := make([]SigningKeyEntry, len(signers))
	for i, signer := range signers {
		signingKeys[i] = signer.signingKey
	}
	event, err := party.chat.DecryptEvent(DecryptEventParams{EventB64: change.eventB64, SigningKeys: signingKeys})
	if err != nil {
		t.Fatalf("DecryptEvent failed: %v", err)
	}
	keyChange := event.AsKeyChange()
	if keyChange == nil {
		t.Fatalf("expected a KeyChange event, got %q", event.Type)
	}
	return keyChange
}

// readCached is the text of message from author, as reader decrypts and
// verifies it on its own with no key map.
func readCached(t *testing.T, reader *signerParty, message string, author *signerParty) string {
	t.Helper()
	event, err := reader.chat.DecryptEvent(DecryptEventParams{
		EventB64:    message,
		SigningKeys: []SigningKeyEntry{author.signingKey},
	})
	msg := mustMessage(t, event, err)
	if !msg.Verified {
		t.Error("expected the message to verify")
	}
	return msg.Text()
}

// newerKeyChange is a key change signer makes in the group for members at a
// later key version than older's.
func newerKeyChange(t *testing.T, signer *signerParty, members []*signerParty, older signedKeyChange) signedKeyChange {
	t.Helper()
	olderVersion, err := strconv.ParseUint(older.version, 10, 64)
	if err != nil {
		t.Fatalf("key version %q is not a number: %v", older.version, err)
	}
	for {
		change := newSignedKeyChange(t, signer, members, signerGroup)
		version, err := strconv.ParseUint(change.version, 10, 64)
		if err != nil {
			t.Fatalf("key version %q is not a number: %v", change.version, err)
		}
		if version > olderVersion {
			return change
		}
	}
}

func TestDecryptEventCachesKeyOfKeyChangeThatVerifies(t *testing.T) {
	admin := newSignerParty(t, "5001")
	member := newSignerParty(t, "5002")
	bot := newCachingParty(t, "5003")
	change := newSignedKeyChange(t, admin, []*signerParty{admin, member, bot}, signerGroup)
	message := signerMessage(t, member, signerGroup, change, "hello group")

	// Nothing is cached yet.
	assertNoCachedKey(t, bot)

	if keyChange := decryptKeyChange(t, bot, change, admin); !keyChange.Verified {
		t.Fatal("expected the key change to verify")
	}

	assertSendsUnder(t, bot, change.version)
	assertEqual(t, "message", readCached(t, bot, message, member), "hello group")
}

func TestDecryptEventDoesNotCacheKeyChangeThatDoesNotVerify(t *testing.T) {
	admin := newSignerParty(t, "5001")
	bot := newCachingParty(t, "5003")
	bot.chat.SetRejectUnverified(false)
	change := newSignedKeyChange(t, admin, []*signerParty{admin, bot}, signerGroup)

	// Without the admin's signing keys the key change is returned unverified.
	if keyChange := decryptKeyChange(t, bot, change); keyChange.Verified {
		t.Fatal("expected the key change not to verify")
	}
	assertNoCachedKey(t, bot)
}

func TestPrepareCallsCacheTheKeyTheyMake(t *testing.T) {
	member := newSignerParty(t, "5002")
	joiner := newSignerParty(t, "5004")
	// The four calls that make a conversation key, as admin makes them.
	prepares := func(admin *signerParty) []func() (*PreparedConversationChange, error) {
		both := []PublicKeyInput{admin.publicKey, member.publicKey}
		return []func() (*PreparedConversationChange, error){
			func() (*PreparedConversationChange, error) {
				return admin.chat.PrepareGroupCreate(GroupCreateParams{
					PublicKeys:     both,
					ConversationID: signerGroup,
					MemberIDs:      []string{admin.userID, member.userID},
					AdminIDs:       []string{admin.userID},
				})
			},
			func() (*PreparedConversationChange, error) {
				return admin.chat.PrepareGroupMembersChange(GroupMembersChangeParams{
					PublicKeys:       []PublicKeyInput{admin.publicKey, member.publicKey, joiner.publicKey},
					ConversationID:   signerGroup,
					NewMemberIDs:     []string{joiner.userID},
					CurrentMemberIDs: []string{admin.userID, member.userID},
					CurrentAdminIDs:  []string{admin.userID},
				})
			},
			func() (*PreparedConversationChange, error) {
				return admin.chat.PrepareGroupMembersRemove(GroupMembersRemoveParams{
					PublicKeys:     both,
					ConversationID: signerGroup,
					UserIDs:        []string{joiner.userID},
				})
			},
			func() (*PreparedConversationChange, error) {
				return admin.chat.PrepareConversationKeyChange(ConversationKeyChangeParams{
					PublicKeys:     both,
					ConversationID: signerGroup,
				})
			},
		}
	}

	// With the cache on, a send that passes no key uses the key each call
	// made.
	admin := newCachingParty(t, "5001")
	for i, prepare := range prepares(admin) {
		prepared, err := prepare()
		if err != nil {
			t.Fatalf("prepare call %d failed: %v", i, err)
		}
		assertSendsUnder(t, admin, prepared.ConversationKeyVersion)
	}

	// With the cache off, the keys are not kept.
	uncached := newSessionParty(t, "5001")
	for i, prepare := range prepares(uncached) {
		if _, err := prepare(); err != nil {
			t.Fatalf("prepare call %d failed: %v", i, err)
		}
		assertNoCachedKey(t, uncached)
	}
}

func TestKeyCacheKeepsEveryVersionAndSendsUseTheNewest(t *testing.T) {
	admin := newSignerParty(t, "5001")
	member := newSignerParty(t, "5002")
	bot := newCachingParty(t, "5003")
	members := []*signerParty{admin, member, bot}
	first := newSignedKeyChange(t, admin, members, signerGroup)
	second := newerKeyChange(t, admin, members, first)

	// The older key change arrives last: it is kept for decryption and does
	// not become the key sends use.
	for _, change := range []signedKeyChange{second, first} {
		if keyChange := decryptKeyChange(t, bot, change, admin); !keyChange.Verified {
			t.Fatalf("expected the key change at version %s to verify", change.version)
		}
	}
	assertSendsUnder(t, bot, second.version)

	for _, change := range []signedKeyChange{first, second} {
		message := signerMessage(t, member, signerGroup, change, "under "+change.version)
		assertEqual(t, "message", readCached(t, bot, message, member), "under "+change.version)
	}
}

func TestFileDecryptionReadsTheKeyCache(t *testing.T) {
	sender := newCachingParty(t, "5001")
	change := newSignedKeyChange(t, sender, []*signerParty{sender}, signerGroup)

	// A message and its file, encrypted under the cached key.
	payload, err := sender.chat.EncryptMessage(EncryptMessageParams{
		ConversationID: signerGroup,
		Text:           "a photo",
		Attachments:    []AttachmentDescriptor{mediaAttachment("photo")},
	})
	if err != nil {
		t.Fatalf("EncryptMessage with no key failed: %v", err)
	}
	assertEqual(t, "key version", payload.ConversationKeyVersion, change.version)
	file := []byte("photo bytes")
	encrypted, err := sender.chat.EncryptFile(EncryptFileParams{File: file, EventB64: payload.EventB64, MediaHashKey: "photo"})
	if err != nil {
		t.Fatalf("EncryptFile with no key failed: %v", err)
	}

	// No key map: the keys come from the cache.
	decrypted, err := sender.chat.DecryptFile(DecryptFileParams{
		Encrypted: encrypted, EventB64: payload.EventB64, MediaHashKey: "photo",
	})
	if err != nil || !bytes.Equal(decrypted, file) {
		t.Fatalf("DecryptFile = %q, %v; want %q", decrypted, err, file)
	}
	decryptor, err := sender.chat.FileDecryptor(FileDecryptorParams{EventB64: payload.EventB64, MediaHashKey: "photo"})
	if err != nil {
		t.Fatalf("FileDecryptor with no key map failed: %v", err)
	}
	defer decryptor.Close()
	streamed, err := decryptor.Push(encrypted)
	if err != nil {
		t.Fatalf("Push failed: %v", err)
	}
	last, err := decryptor.Finish()
	if err != nil {
		t.Fatalf("Finish failed: %v", err)
	}
	if streamed = append(streamed, last...); !bytes.Equal(streamed, file) {
		t.Fatalf("FileDecryptor = %q; want %q", streamed, file)
	}

	// A key map that is passed is the only source: one without the message's
	// version fails though the cache holds that version.
	otherVersion := map[string][]byte{"9": bytes.Repeat([]byte{7}, 32)}
	noKey := "conversation_keys has no key for version '" + change.version + "'"
	if _, err := sender.chat.DecryptFile(DecryptFileParams{
		Encrypted: encrypted, EventB64: payload.EventB64, ConversationKeys: otherVersion, MediaHashKey: "photo",
	}); err == nil {
		t.Error("expected DecryptFile to fail with a key map without the message's version")
	} else {
		assertContains(t, "DecryptFile error", err.Error(), noKey)
	}
	if other, err := sender.chat.FileDecryptor(FileDecryptorParams{
		EventB64: payload.EventB64, ConversationKeys: otherVersion, MediaHashKey: "photo",
	}); err == nil {
		other.Close()
		t.Error("expected FileDecryptor to fail with a key map without the message's version")
	} else {
		assertContains(t, "FileDecryptor error", err.Error(), noKey)
	}
}

func TestPrepareGroupAvatarChangeSignsTheNewestCachedVersion(t *testing.T) {
	admin := newCachingParty(t, "5001")
	avatarURL := "https://ton.x.com/xchat_media/g900/avatar"
	// Whether the avatar change admin prepares with params signs version.
	signs := func(params GroupAvatarChangeParams, version string) bool {
		t.Helper()
		prepared, err := admin.chat.PrepareGroupAvatarChange(params)
		signature := onlyAction(t, prepared, err)
		return signedOver(t, admin.chat, signature, "GroupChangeEvent.GroupAvatarUrlChange,"+signature.MessageID+
			","+admin.userID+","+signerGroup+","+version+","+avatarURL)
	}
	omitted := GroupAvatarChangeParams{ConversationID: signerGroup, NewAvatarURL: avatarURL}

	// With no key cached there is no version to sign.
	_, err := admin.chat.PrepareGroupAvatarChange(omitted)
	var chatErr *Error
	if !errors.As(err, &chatErr) || chatErr.Kind != ErrorKindInvalidState {
		t.Fatalf("expected an invalid-state error with no key cached, got %v", err)
	}
	assertContains(t, "error", chatErr.Message,
		"conversation_key_version is not set and no conversation key is cached for '"+signerGroup+"'")

	first := newSignedKeyChange(t, admin, []*signerParty{admin}, signerGroup)
	second := newerKeyChange(t, admin, []*signerParty{admin}, first)
	if !signs(omitted, second.version) {
		t.Errorf("expected the avatar change to sign the newest cached version, %s", second.version)
	}

	// A version that is passed is signed as is.
	explicit := omitted
	explicit.ConversationKeyVersion = first.version
	if !signs(explicit, first.version) {
		t.Errorf("expected the avatar change to sign the version passed, %s", first.version)
	}
}

func TestAddSigningKeysAddsToTheStoredKeysAndSetSigningKeysReplacesThem(t *testing.T) {
	alice := newSignerParty(t, "5001")
	bob := newSignerParty(t, "5002")
	reader := newSignerParty(t, "5003")
	shared := signedKeyChange{key: bytes.Repeat([]byte{7}, 32), version: "7"}
	// Whether reader decrypts a message from author and verifies it with the
	// signing keys it stores.
	reads := func(author *signerParty) bool {
		t.Helper()
		event, err := reader.chat.DecryptEvent(DecryptEventParams{
			EventB64:         signerMessage(t, author, signerGroup, shared, "hi"),
			ConversationKeys: map[string][]byte{shared.version: shared.key},
		})
		if err != nil {
			return false
		}
		message := event.AsMessage()
		return message != nil && message.Verified
	}
	store := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s failed: %v", what, err)
		}
	}

	store("SetSigningKeys", reader.chat.SetSigningKeys([]SigningKeyEntry{alice.signingKey}))
	if !reads(alice) || reads(bob) {
		t.Fatal("expected only alice's messages to verify with her keys stored")
	}

	// Adding keeps what is stored.
	store("AddSigningKeys", reader.chat.AddSigningKeys([]SigningKeyEntry{bob.signingKey}))
	if !reads(alice) || !reads(bob) {
		t.Fatal("expected both to verify after adding bob's keys")
	}

	// An entry for a stored user and key version replaces that entry alone.
	wrong := bob.signingKey
	wrong.UserID = alice.userID
	store("AddSigningKeys", reader.chat.AddSigningKeys([]SigningKeyEntry{wrong}))
	if reads(alice) || !reads(bob) {
		t.Fatal("expected the added entry to replace alice's alone")
	}

	// Nil adds nothing.
	store("AddSigningKeys", reader.chat.AddSigningKeys(nil))
	if reads(alice) || !reads(bob) {
		t.Fatal("expected nil to add nothing")
	}

	// Setting replaces the whole set.
	store("SetSigningKeys", reader.chat.SetSigningKeys([]SigningKeyEntry{bob.signingKey}))
	if reads(alice) || !reads(bob) {
		t.Fatal("expected only bob's messages to verify with his keys alone stored")
	}
}
