package main

import (
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/xdevplatform/chat-xdk/go/chatxdk"
)

// signIn is the chat that chats keeps for the user p, signed in with p's
// keys. The chat is released when the test ends.
func signIn(t *testing.T, chats *UserChats, p *party) *ChatCore {
	t.Helper()
	chat, err := chats.ChatFor(p.userID, p.privateKeysB64, "1")
	if err != nil {
		t.Fatalf("ChatFor: %v", err)
	}
	t.Cleanup(func() { chats.Close(p.userID) })
	return chat
}

func TestChatsOfTwoSignedInUsersFetchTheKeysOfAUserTheyBothMeetOnce(t *testing.T) {
	admin, member := newParty(t, "5001"), newParty(t, "5002")
	alice, bob := newParty(t, "5003"), newParty(t, "5004")
	directory := directoryOf(admin, member)
	chats := NewUserChats(NewSharedPublicKeys(directory.fetch, PublicKeysTTL).Resolve)
	keyChange, message := keyChangeAndMessage(t, admin, []*party{admin, member, alice, bob}, member, "hello group")
	events := []string{keyChange, message}

	for _, signedIn := range []*party{alice, bob} {
		result, err := signIn(t, chats, signedIn).DecryptBatch(events)
		if err != nil {
			t.Fatalf("DecryptBatch: %v", err)
		}
		if len(result.Errors) != 0 || len(result.MissingSigningKeys) != 0 {
			t.Fatalf("user %s: decrypt errors %v, missing signing keys %v", signedIn.userID, result.Errors, result.MissingSigningKeys)
		}
		if texts := messageTexts(result); !reflect.DeepEqual(texts, []string{"", "hello group"}) {
			t.Errorf("user %s: expected the key change and the message, got %q", signedIn.userID, texts)
		}
	}
	// Each chat needed the keys of the admin and the member: the second chat
	// took them from the cache the first one filled.
	asked := directory.askedFor()
	sort.Strings(asked)
	if !reflect.DeepEqual(asked, []string{"5001", "5002"}) {
		t.Errorf("asked for the keys of %v, want [5001 5002]", asked)
	}
}

func TestASignedInUserHasOneChatForEveryConversation(t *testing.T) {
	admin, member := newParty(t, "5001"), newParty(t, "5002")
	alice, bob := newParty(t, "5003"), newParty(t, "5004")
	chats := NewUserChats(NewSharedPublicKeys(directoryOf(admin, member).fetch, PublicKeysTTL).Resolve)

	// Calls for one user get one chat, also when they are made at the same
	// time, and another user gets another chat.
	var wg sync.WaitGroup
	sameUser := make([]*ChatCore, 4)
	for i := range sameUser {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sameUser[i], _ = chats.ChatFor(alice.userID, alice.privateKeysB64, "1")
		}(i)
	}
	wg.Wait()
	chat := signIn(t, chats, alice)
	for _, core := range sameUser {
		if core != chat {
			t.Fatal("expected every call for one user to get the same chat")
		}
	}
	if signIn(t, chats, bob) == chat {
		t.Fatal("expected another chat for another user")
	}

	for _, conversationID := range []string{testGroup, "g901"} {
		text := "hello " + conversationID
		keyChange, message := keyChangeAndMessageIn(t, conversationID, admin, []*party{admin, member, alice}, member, text)
		result, err := chat.DecryptBatch([]string{keyChange, message})
		if err != nil {
			t.Fatalf("DecryptBatch: %v", err)
		}
		if texts := messageTexts(result); !reflect.DeepEqual(texts, []string{"", text}) {
			t.Fatalf("%s: expected the key change and the message, got %q, errors %v", conversationID, texts, result.Errors)
		}
		// The reply takes the conversation's key from the chat's key cache.
		body, err := chat.EncryptReply(conversationID, "hi", nil)
		if err != nil {
			t.Fatalf("EncryptReply in %s: %v", conversationID, err)
		}
		if body.EncodedMessageCreateEvent == "" {
			t.Errorf("%s: empty encoded_message_create_event", conversationID)
		}
	}
	// The chat holds no key for a conversation it has not read.
	if _, err := chat.EncryptReply("g902", "hi", nil); err == nil {
		t.Error("expected an error in a conversation the chat has not read")
	}

	// After a sign-out, the next sign-in makes another chat.
	chats.Close(alice.userID)
	if signIn(t, chats, alice) == chat {
		t.Error("expected another chat after the user signed out")
	}
}

func TestSharedPublicKeysSharesALookupRetriesAFailureAndFetchesAgainAfterTheTTL(t *testing.T) {
	five := []chatxdk.PublicKeyRecord{{PublicKeyVersion: "1"}}
	seven := []chatxdk.PublicKeyRecord{{PublicKeyVersion: "2"}}
	onlyFive := map[string][]chatxdk.PublicKeyRecord{"5": five}
	onlySeven := map[string][]chatxdk.PublicKeyRecord{"7": seven}
	directory := &publicKeyDirectory{records: map[string][]chatxdk.PublicKeyRecord{"5": five}}
	// The first fetch says that it started and waits to be released.
	started, release := make(chan struct{}), make(chan struct{})
	var first sync.Once
	shared := NewSharedPublicKeys(func(userID string) ([]chatxdk.PublicKeyRecord, error) {
		first.Do(func() {
			close(started)
			<-release
		})
		return directory.fetch(userID)
	}, 100*time.Millisecond)
	clock := time.Unix(1_000, 0)
	shared.now = func() time.Time { return clock }
	resolve := func(userIDs ...string) map[string][]chatxdk.PublicKeyRecord {
		records, err := shared.Resolve(userIDs)
		if err != nil {
			t.Errorf("Resolve: %v", err)
		}
		return records
	}

	// A second call for user 5 is made while the fetch of the first call is
	// under way: the fetch runs once, and both calls get its answer. A second
	// call that reaches the cache after the fetch returned gets it as well.
	answers := make(chan map[string][]chatxdk.PublicKeyRecord, 2)
	go func() { answers <- resolve("5") }()
	<-started
	go func() { answers <- resolve("5") }()
	close(release)
	for i := 0; i < 2; i++ {
		if got := <-answers; !reflect.DeepEqual(got, onlyFive) {
			t.Errorf("got %v, want %v", got, onlyFive)
		}
	}
	if asked := directory.askedFor(); !reflect.DeepEqual(asked, []string{"5"}) {
		t.Fatalf("fetched the keys of %v, want [5]", asked)
	}

	// A lookup that fails leaves its user out of the answer, which still
	// holds the other users, and is not kept: the next call fetches again.
	if got := resolve("5", "7"); !reflect.DeepEqual(got, onlyFive) {
		t.Errorf("got %v, want %v", got, onlyFive)
	}
	directory.records["7"] = seven
	if got := resolve("7"); !reflect.DeepEqual(got, onlySeven) {
		t.Errorf("got %v, want %v", got, onlySeven)
	}
	if asked := directory.askedFor(); !reflect.DeepEqual(asked, []string{"5", "7", "7"}) {
		t.Fatalf("fetched the keys of %v, want [5 7 7]", asked)
	}

	// An answer is served until its time is up, then fetched again.
	clock = clock.Add(99 * time.Millisecond)
	if got := resolve("5"); !reflect.DeepEqual(got, onlyFive) {
		t.Errorf("got %v, want %v", got, onlyFive)
	}
	if asked := directory.askedFor(); len(asked) != 3 {
		t.Errorf("expected no further fetch, fetched the keys of %v", asked)
	}
	clock = clock.Add(time.Millisecond)
	if got := resolve("5"); !reflect.DeepEqual(got, onlyFive) {
		t.Errorf("got %v, want %v", got, onlyFive)
	}
	if asked := directory.askedFor(); !reflect.DeepEqual(asked, []string{"5", "7", "7", "5"}) {
		t.Errorf("fetched the keys of %v, want [5 7 7 5]", asked)
	}
	// That lookup also removed the answer for user 7, whose time was up too.
	if len(shared.lookups) != 1 {
		t.Errorf("expected the cache to hold user 5 alone, got %d users", len(shared.lookups))
	}
}
