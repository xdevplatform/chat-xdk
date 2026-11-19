package chatxdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"testing"
)

// Other users' public keys: the signing keys a batch reports missing, the
// records AddPublicKeys stores, the keys prepare calls read from the store,
// and the hook that fetches what is missing.

// publicKeyRecordOf is the record the X API returns for party's keys.
func publicKeyRecordOf(party *signerParty) PublicKeyRecord {
	return PublicKeyRecord{
		PublicKeyVersion:           signerKeyVersion,
		PublicKey:                  party.signingKey.IdentityPublicKey,
		SigningPublicKey:           party.signingKey.PublicKey,
		IdentityPublicKeySignature: party.signingKey.IdentityPublicKeySignature,
	}
}

// apiPublicKeys is the data of the body GET /2/users/{id}/public_keys
// returns for party's keys, read as a caller reads it. The body writes the
// key version as version, a JSON string or number, and carries a field the
// SDK does not read.
func apiPublicKeys(t *testing.T, party *signerParty, version string) []PublicKeyRecord {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"data": []map[string]any{{
			"public_key_version":            json.RawMessage(version),
			"public_key":                    party.signingKey.IdentityPublicKey,
			"signing_public_key":            party.signingKey.PublicKey,
			"identity_public_key_signature": party.signingKey.IdentityPublicKeySignature,
			"juicebox_config":               map[string]any{"realms": []any{}},
		}},
	})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var response struct {
		Data []PublicKeyRecord `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	return response.Data
}

// publicKeyDirectory holds users' public-key records by user id. Its resolve
// method is a SetResolvePublicKeys hook that answers from them and keeps the
// user ids of each call it gets.
type publicKeyDirectory struct {
	records map[string][]PublicKeyRecord
	calls   [][]string
}

func newPublicKeyDirectory(parties ...*signerParty) *publicKeyDirectory {
	records := make(map[string][]PublicKeyRecord, len(parties))
	for _, party := range parties {
		records[party.userID] = []PublicKeyRecord{publicKeyRecordOf(party)}
	}
	return &publicKeyDirectory{records: records}
}

func (d *publicKeyDirectory) resolve(userIDs []string) (map[string][]PublicKeyRecord, error) {
	d.calls = append(d.calls, append([]string(nil), userIDs...))
	found := make(map[string][]PublicKeyRecord)
	for _, userID := range userIDs {
		if records, ok := d.records[userID]; ok {
			found[userID] = records
		}
	}
	return found, nil
}

// recipientsOf is the users a prepared change encrypted its key to, sorted.
func recipientsOf(prepared *PreparedConversationChange) []string {
	userIDs := make([]string, len(prepared.ConversationParticipantKeys))
	for i, key := range prepared.ConversationParticipantKeys {
		userIDs[i] = key.UserID
	}
	sort.Strings(userIDs)
	return userIDs
}

// keylessPrepare is a prepare call that passes no public keys, as user 5001
// makes it, with the users it encrypts its key to in the order the call
// names them.
type keylessPrepare struct {
	name       string
	recipients []string
	prepare    func(chat *Chat) (*PreparedConversationChange, error)
}

// keylessPrepares is each call that makes a conversation key, passing no
// public keys: a group of 5001 and 5002 is created, 5004 is added to it and
// removed from it, its key is rotated, and 5001 starts a one-to-one with
// 5002, named by the other user's id.
func keylessPrepares() []keylessPrepare {
	return []keylessPrepare{
		{"group create", []string{"5001", "5002"}, func(chat *Chat) (*PreparedConversationChange, error) {
			return chat.PrepareGroupCreate(GroupCreateParams{
				ConversationID: signerGroup,
				MemberIDs:      []string{"5001", "5002"},
				AdminIDs:       []string{"5001"},
			})
		}},
		{"members change", []string{"5001", "5002", "5004"}, func(chat *Chat) (*PreparedConversationChange, error) {
			return chat.PrepareGroupMembersChange(GroupMembersChangeParams{
				ConversationID:   signerGroup,
				NewMemberIDs:     []string{"5004"},
				CurrentMemberIDs: []string{"5001", "5002"},
				CurrentAdminIDs:  []string{"5001"},
			})
		}},
		{"members remove", []string{"5001", "5002"}, func(chat *Chat) (*PreparedConversationChange, error) {
			return chat.PrepareGroupMembersRemove(GroupMembersRemoveParams{
				ConversationID:     signerGroup,
				UserIDs:            []string{"5004"},
				RemainingMemberIDs: []string{"5001", "5002"},
			})
		}},
		{"key change", []string{"5001", "5002"}, func(chat *Chat) (*PreparedConversationChange, error) {
			return chat.PrepareConversationKeyChange(ConversationKeyChangeParams{
				ConversationID: signerGroup,
				MemberIDs:      []string{"5001", "5002"},
			})
		}},
		{"one-to-one key change", []string{"5001", "5002"}, func(chat *Chat) (*PreparedConversationChange, error) {
			return chat.PrepareConversationKeyChange(ConversationKeyChangeParams{ConversationID: "5002"})
		}},
	}
}

// assertEncryptedTo checks that prepared encrypted its key to recipients
// alone, and that member, one of them, decrypts the key it holds for it.
func assertEncryptedTo(t *testing.T, what string, prepared *PreparedConversationChange, recipients []string, member *signerParty) {
	t.Helper()
	assertEqual(t, what+" recipients", recipientsOf(prepared), recipients)
	for _, key := range prepared.ConversationParticipantKeys {
		if key.UserID != member.userID {
			continue
		}
		decrypted, err := member.chat.DecryptConversationKey(key.EncryptedConversationKey)
		if err != nil {
			t.Fatalf("%s: DecryptConversationKey failed: %v", what, err)
		}
		if !bytes.Equal(decrypted, prepared.ConversationKey) {
			t.Errorf("%s: user %s decrypted another key than the call made", what, member.userID)
		}
	}
}

// groupOfTwo is the params of a create of the group for 5001 and 5002 that
// passes no public keys.
func groupOfTwo() GroupCreateParams {
	return GroupCreateParams{
		ConversationID: signerGroup,
		MemberIDs:      []string{"5001", "5002"},
		AdminIDs:       []string{"5001"},
	}
}

func TestDecryptEventsReportsTheSigningKeysItLacked(t *testing.T) {
	page := newSignerPage(t)
	bot := page.bot.chat

	// With no signing keys, the result names the key each event needed.
	result := page.decrypt(t, page.events)
	if len(result.Events) != 0 {
		t.Errorf("expected no decrypted events, got %d", len(result.Events))
	}
	assertEqual(t, "missing signing keys", result.MissingSigningKeys, map[string]MissingSigningKey{
		"0": {UserID: "5001", PublicKeyVersion: signerKeyVersion},
		"1": {UserID: "5002", PublicKeyVersion: signerKeyVersion},
	})

	// The users to fetch keys for come in batch order, and are not asked for
	// again at once.
	missing, err := bot.MissingPublicKeys(result)
	if err != nil {
		t.Fatalf("MissingPublicKeys failed: %v", err)
	}
	assertEqual(t, "missing public keys", missing, []string{"5001", "5002"})
	missing, err = bot.MissingPublicKeys(result)
	if err != nil {
		t.Fatalf("MissingPublicKeys failed: %v", err)
	}
	if len(missing) != 0 {
		t.Errorf("expected no user to be asked for again, got %v", missing)
	}

	// With the member's keys given, only the admin's is missing.
	result = page.decrypt(t, page.events, page.member)
	assertEqual(t, "missing signing keys", result.MissingSigningKeys, map[string]MissingSigningKey{
		"0": {UserID: "5001", PublicKeyVersion: signerKeyVersion},
	})

	// A result that lacked no key names no user.
	result = page.decrypt(t, page.events, page.member, page.admin)
	assertEqual(t, "missing signing keys", result.MissingSigningKeys, map[string]MissingSigningKey{})
	missing, err = bot.MissingPublicKeys(result)
	if err != nil {
		t.Fatalf("MissingPublicKeys failed: %v", err)
	}
	if len(missing) != 0 {
		t.Errorf("expected no missing public keys, got %v", missing)
	}
}

func TestPublicKeyRecordReadsTheAPIsJSON(t *testing.T) {
	admin := newSignerParty(t, "5001")
	want := []PublicKeyRecord{publicKeyRecordOf(admin)}

	// The key version is read whether the body writes it as a string or as
	// a number, and a field the SDK does not read is ignored.
	assertEqual(t, "record", apiPublicKeys(t, admin, `"1"`), want)
	assertEqual(t, "record with a numeric key version", apiPublicKeys(t, admin, `1`), want)

	// A field that is null or absent is empty.
	var record PublicKeyRecord
	if err := json.Unmarshal([]byte(`{"public_key_version":null,"public_key":"abc"}`), &record); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	assertEqual(t, "partial record", record, PublicKeyRecord{PublicKey: "abc"})

	// A key version that is neither a string nor a number is an error.
	if err := json.Unmarshal([]byte(`{"public_key_version":true}`), &record); err == nil {
		t.Error("expected a boolean key version to fail")
	}

	// A record is written under the names the API uses.
	written, err := json.Marshal(PublicKeyRecord{
		PublicKeyVersion:           "1",
		PublicKey:                  "identity",
		SigningPublicKey:           "signing",
		IdentityPublicKeySignature: "binding",
	})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	assertEqual(t, "written record", string(written),
		`{"public_key_version":"1","public_key":"identity","signing_public_key":"signing","identity_public_key_signature":"binding"}`)
}

func TestAddPublicKeysStoresTheRecordsTheAPIReturns(t *testing.T) {
	page := newSignerPage(t)
	bot := page.bot.chat

	// Nothing, and a user whose lookup found nothing, add no key.
	if err := bot.AddPublicKeys(nil); err != nil {
		t.Fatalf("AddPublicKeys failed: %v", err)
	}
	if err := bot.AddPublicKeys(map[string][]PublicKeyRecord{"5001": nil, "5002": {}}); err != nil {
		t.Fatalf("AddPublicKeys failed: %v", err)
	}
	// A record without its signing key is left out.
	partial := publicKeyRecordOf(page.admin)
	partial.SigningPublicKey = ""
	if err := bot.AddPublicKeys(map[string][]PublicKeyRecord{"5001": {partial}}); err != nil {
		t.Fatalf("AddPublicKeys failed: %v", err)
	}
	if result := page.decrypt(t, page.events); len(result.Events) != 0 {
		t.Fatalf("expected no decrypted events, got %d", len(result.Events))
	}

	// The records as the API returns them make the page decrypt with no
	// signing keys passed.
	err := bot.AddPublicKeys(map[string][]PublicKeyRecord{
		"5001": apiPublicKeys(t, page.admin, `"1"`),
		"5002": apiPublicKeys(t, page.member, `1`),
	})
	if err != nil {
		t.Fatalf("AddPublicKeys failed: %v", err)
	}
	result := page.decrypt(t, page.events)
	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", result.Errors)
	}
	assertEqual(t, "missing signing keys", result.MissingSigningKeys, map[string]MissingSigningKey{})
	assertEqual(t, "unverified key changes", result.UnverifiedKeyChanges, map[string]UnverifiedKeyChange{})
	if len(result.Events) != 2 || result.Events[0].Event.Type != "KeyChange" {
		t.Fatalf("expected a key change and a message, got %+v", result.Events)
	}
	assertEqual(t, "messages", messageTexts(result), []string{"hello group"})
}

func TestDecryptEventsFetchesMissingKeysThroughTheHook(t *testing.T) {
	page := newSignerPage(t)
	bot := page.bot
	if err := bot.chat.SetIdentity(SetIdentityParams{UserID: bot.userID, SigningKeyVersion: signerKeyVersion}); err != nil {
		t.Fatalf("SetIdentity failed: %v", err)
	}
	directory := newPublicKeyDirectory(page.admin, page.member)
	bot.chat.SetResolvePublicKeys(directory.resolve)

	// The hook is asked once for the two users whose keys the page needs,
	// and the page then decrypts.
	result := page.decrypt(t, page.events)
	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", result.Errors)
	}
	assertEqual(t, "missing signing keys", result.MissingSigningKeys, map[string]MissingSigningKey{})
	if len(result.Events) != 2 || result.Events[0].Event.Type != "KeyChange" {
		t.Fatalf("expected a key change and a message, got %+v", result.Events)
	}
	assertEqual(t, "messages", messageTexts(result), []string{"hello group"})
	assertEqual(t, "hook calls", directory.calls, [][]string{{"5001", "5002"}})

	// Setting the hook turned the key cache on: a send that passes no key
	// finds the key of the verified key change.
	assertSendsUnder(t, bot, page.change.version)

	// The keys are stored: the next batch needs no lookup.
	result = page.decrypt(t, page.events)
	assertEqual(t, "messages", messageTexts(result), []string{"hello group"})
	if len(directory.calls) != 1 {
		t.Errorf("expected no further hook call, got %v", directory.calls)
	}

	// Removing the hook leaves the key cache on.
	bot.chat.SetResolvePublicKeys(nil)
	assertSendsUnder(t, bot, page.change.version)
}

func TestDecryptEventsDoesNotCallTheHookForKeysPassedOrNotFound(t *testing.T) {
	page := newSignerPage(t)
	// The hook knows the admin alone.
	directory := newPublicKeyDirectory(page.admin)
	page.bot.chat.SetResolvePublicKeys(directory.resolve)

	// Signing keys that are passed are what the call verifies with.
	result := page.decrypt(t, page.events, page.member)
	assertEqual(t, "missing signing keys", result.MissingSigningKeys, map[string]MissingSigningKey{
		"0": {UserID: "5001", PublicKeyVersion: signerKeyVersion},
	})
	if len(directory.calls) != 0 {
		t.Fatalf("expected no hook call, got %v", directory.calls)
	}

	// The member's keys are not found: the result says so, and the next
	// call does not ask again.
	result = page.decrypt(t, page.events)
	assertEqual(t, "missing signing keys", result.MissingSigningKeys, map[string]MissingSigningKey{
		"1": {UserID: "5002", PublicKeyVersion: signerKeyVersion},
	})
	if len(result.Events) != 1 || result.Events[0].Event.Type != "KeyChange" {
		t.Errorf("expected the key change alone, got %+v", result.Events)
	}
	assertEqual(t, "hook calls", directory.calls, [][]string{{"5001", "5002"}})
	result = page.decrypt(t, page.events)
	assertEqual(t, "missing signing keys", result.MissingSigningKeys, map[string]MissingSigningKey{
		"1": {UserID: "5002", PublicKeyVersion: signerKeyVersion},
	})
	if len(directory.calls) != 1 {
		t.Errorf("expected no further hook call, got %v", directory.calls)
	}
}

func TestDecryptEventsReturnsTheErrorOfTheHook(t *testing.T) {
	page := newSignerPage(t)
	failure := errors.New("public keys lookup failed")
	page.bot.chat.SetResolvePublicKeys(func([]string) (map[string][]PublicKeyRecord, error) {
		return nil, failure
	})

	_, err := page.bot.chat.DecryptEvents(DecryptEventsParams{Events: page.events})
	if !errors.Is(err, failure) {
		t.Fatalf("expected the hook's error, got %v", err)
	}

	// With the hook removed, the call reports the keys it lacked.
	page.bot.chat.SetResolvePublicKeys(nil)
	result := page.decrypt(t, page.events)
	if len(result.MissingSigningKeys) != 2 {
		t.Errorf("expected two missing signing keys, got %v", result.MissingSigningKeys)
	}
}

func TestPrepareCallsEncryptToStoredPublicKeys(t *testing.T) {
	admin := newSessionParty(t, "5001")
	member := newSignerParty(t, "5002")
	joiner := newSignerParty(t, "5004")
	if err := admin.chat.AddPublicKeys(newPublicKeyDirectory(admin, member, joiner).records); err != nil {
		t.Fatalf("AddPublicKeys failed: %v", err)
	}

	for _, call := range keylessPrepares() {
		prepared, err := call.prepare(admin.chat)
		if err != nil {
			t.Fatalf("%s failed: %v", call.name, err)
		}
		assertEncryptedTo(t, call.name, prepared, call.recipients, member)
		if call.name == "one-to-one key change" && prepared.ConversationID != "5001:5002" {
			t.Errorf("unexpected one-to-one conversation id %q", prepared.ConversationID)
		}
	}
}

func TestPrepareCallsNameTheUsersWithoutStoredPublicKeys(t *testing.T) {
	admin := newSessionParty(t, "5001")
	if err := admin.chat.AddPublicKeys(newPublicKeyDirectory(admin).records); err != nil {
		t.Fatalf("AddPublicKeys failed: %v", err)
	}

	_, err := admin.chat.PrepareGroupCreate(groupOfTwo())
	var chatErr *Error
	if !errors.As(err, &chatErr) || chatErr.Kind != ErrorKindInvalidInput {
		t.Fatalf("expected an invalid-input error, got %v", err)
	}
	assertContains(t, "error", chatErr.Message, "no public keys are stored for user(s) 5002")

	// The call names that user to look up, once.
	missing, err := admin.chat.missingPublicKeysFor(callGroupCreate, groupOfTwo())
	if err != nil {
		t.Fatalf("missingPublicKeysFor failed: %v", err)
	}
	assertEqual(t, "missing public keys", missing, []string{"5002"})
	missing, err = admin.chat.missingPublicKeysFor(callGroupCreate, groupOfTwo())
	if err != nil {
		t.Fatalf("missingPublicKeysFor failed: %v", err)
	}
	if len(missing) != 0 {
		t.Errorf("expected no user to be asked for again, got %v", missing)
	}

	// A call the native side does not know is an error.
	_, err = admin.chat.missingPublicKeysFor("group_leave", groupOfTwo())
	if !errors.As(err, &chatErr) || chatErr.Kind != ErrorKindInvalidInput {
		t.Errorf("expected an invalid-input error, got %v", err)
	}

	// Without members to read keys for, a call reports its empty public
	// keys as it does with nothing stored.
	_, err = admin.chat.PrepareGroupMembersRemove(GroupMembersRemoveParams{
		ConversationID: signerGroup,
		UserIDs:        []string{"5004"},
	})
	if err == nil {
		t.Fatal("expected a removal with no public keys and no remaining members to fail")
	}
	assertContains(t, "error", err.Error(), "public_keys is empty: pass the public keys of the remaining members")
	_, err = admin.chat.PrepareConversationKeyChange(ConversationKeyChangeParams{ConversationID: signerGroup})
	if err == nil {
		t.Fatal("expected a key change with no public keys and no members to fail")
	}
	assertContains(t, "error", err.Error(), "public_keys must not be empty")
}

func TestPrepareCallsFetchPublicKeysThroughTheHook(t *testing.T) {
	member := newSignerParty(t, "5002")
	joiner := newSignerParty(t, "5004")

	for _, call := range keylessPrepares() {
		// Each call is made by a chat that has no key stored.
		admin := newSessionParty(t, "5001")
		directory := newPublicKeyDirectory(admin, member, joiner)
		admin.chat.SetResolvePublicKeys(directory.resolve)

		prepared, err := call.prepare(admin.chat)
		if err != nil {
			t.Fatalf("%s failed: %v", call.name, err)
		}
		assertEncryptedTo(t, call.name, prepared, call.recipients, member)
		assertEqual(t, call.name+" hook calls", directory.calls, [][]string{call.recipients})

		// The keys are stored: the same call needs no further lookup.
		if _, err := call.prepare(admin.chat); err != nil {
			t.Fatalf("%s failed the second time: %v", call.name, err)
		}
		if len(directory.calls) != 1 {
			t.Errorf("%s: expected no further hook call, got %v", call.name, directory.calls)
		}
	}
}

func TestPrepareCallsDoNotCallTheHookForKeysPassedOrNotFound(t *testing.T) {
	admin := newSessionParty(t, "5001")
	stranger := newSignerParty(t, "5006")
	// The hook knows the admin alone.
	directory := newPublicKeyDirectory(admin)
	admin.chat.SetResolvePublicKeys(directory.resolve)

	// Public keys that are passed are used as they are.
	prepared, err := admin.chat.PrepareGroupCreate(GroupCreateParams{
		PublicKeys:     []PublicKeyInput{admin.publicKey, stranger.publicKey},
		ConversationID: signerGroup,
		MemberIDs:      []string{"5001", "5006"},
		AdminIDs:       []string{"5001"},
	})
	if err != nil {
		t.Fatalf("PrepareGroupCreate failed: %v", err)
	}
	assertEqual(t, "recipients", recipientsOf(prepared), []string{"5001", "5006"})
	if len(directory.calls) != 0 {
		t.Fatalf("expected no hook call, got %v", directory.calls)
	}

	// A member's keys are not found: the call fails naming that member, and
	// the next call does not ask again.
	for attempt := 0; attempt < 2; attempt++ {
		_, err = admin.chat.PrepareGroupCreate(groupOfTwo())
		var chatErr *Error
		if !errors.As(err, &chatErr) || chatErr.Kind != ErrorKindInvalidInput {
			t.Fatalf("expected an invalid-input error, got %v", err)
		}
		assertContains(t, "error", chatErr.Message, "no public keys are stored for user(s) 5002")
		assertEqual(t, "hook calls", directory.calls, [][]string{{"5001", "5002"}})
	}
}

func TestPrepareCallsReturnTheErrorOfTheHook(t *testing.T) {
	admin := newSessionParty(t, "5001")
	failure := errors.New("public keys lookup failed")
	admin.chat.SetResolvePublicKeys(func([]string) (map[string][]PublicKeyRecord, error) {
		return nil, failure
	})

	if _, err := admin.chat.PrepareGroupCreate(groupOfTwo()); !errors.Is(err, failure) {
		t.Fatalf("expected the hook's error, got %v", err)
	}
}
