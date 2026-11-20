// Many signed-in users in one process.
//
// A chat holds one user's private keys and signs as that user. A process
// that serves several signed-in users keeps one chat per user, for all of
// that user's conversations, and never one per conversation: the chat keeps
// its conversation keys by conversation and the public keys it has met by
// user id.
//
// Other users' public keys are the same whichever chat asks, so the chats
// share one function that fetches them:
//
//   - SharedPublicKeys -> a public-key hook over one cache of
//     GET /2/users/{id}/public_keys answers
//   - UserChats        -> one ChatCore per signed-in user, each with that
//     hook

package main

import (
	"log"
	"sync"
	"time"

	"github.com/xdevplatform/chat-xdk/go/chatxdk"
)

// PublicKeysTTL is how long SharedPublicKeys serves a fetched answer before
// it fetches it again, unless it is given another time.
const PublicKeysTTL = 5 * time.Minute

// SharedPublicKeys is one cache of GET /2/users/{id}/public_keys answers, by
// user id, for every chat in the process. Its Resolve method is the SDK's
// public-key hook, so the chats of two signed-in users who meet the same
// user cost one request:
//
//   - Calls that ask for a user whose lookup is under way wait for that
//     lookup.
//   - A lookup that fails is logged and dropped, and the user is left out of
//     the answer: the next call fetches again.
//   - An answer is served for the TTL, then fetched again, so a key a user
//     registers later is picked up.
//
// A SharedPublicKeys may be used from several goroutines at once.
type SharedPublicKeys struct {
	fetch func(userID string) ([]chatxdk.PublicKeyRecord, error)
	ttl   time.Duration
	// now is the clock. A test replaces it to move time without sleeping.
	now func() time.Time

	// mu guards lookups. It is not held while a fetch runs, so lookups of
	// different users do not wait for each other.
	mu      sync.Mutex
	lookups map[string]*publicKeyLookup
}

// publicKeyLookup is one user's lookup: under way until done is closed, and
// an answer from then on.
type publicKeyLookup struct {
	// expires is the time until which the lookup is served.
	expires time.Time
	// done is closed once the fetch has returned. found and records are set
	// before that and never after.
	done chan struct{}
	// found is whether the fetch succeeded.
	found bool
	// records is what the fetch returned.
	records []chatxdk.PublicKeyRecord
}

// NewSharedPublicKeys returns a cache in front of fetch, which returns one
// user's records from GET /2/users/{id}/public_keys: the function
// ChatCore.FetchPublicKeysWith takes. An answer is served for ttl, or for
// PublicKeysTTL when ttl is zero or less.
func NewSharedPublicKeys(fetch func(userID string) ([]chatxdk.PublicKeyRecord, error), ttl time.Duration) *SharedPublicKeys {
	if ttl <= 0 {
		ttl = PublicKeysTTL
	}
	return &SharedPublicKeys{
		fetch:   fetch,
		ttl:     ttl,
		now:     time.Now,
		lookups: map[string]*publicKeyLookup{},
	}
}

// Resolve returns the records of each of userIDs, by user id. It is the
// function chatxdk's SetResolvePublicKeys takes: give it to every chat in
// the process.
//
// The users are looked up at the same time. A user whose lookup fails is
// left out and the error is always nil, so one user's failure does not fail
// the call that needs the keys of the others.
func (s *SharedPublicKeys) Resolve(userIDs []string) (map[string][]chatxdk.PublicKeyRecord, error) {
	lookups := make([]*publicKeyLookup, len(userIDs))
	for i, userID := range userIDs {
		lookups[i] = s.lookUp(userID)
	}
	records := make(map[string][]chatxdk.PublicKeyRecord, len(userIDs))
	for i, userID := range userIDs {
		<-lookups[i].done
		if lookups[i].found {
			records[userID] = lookups[i].records
		}
	}
	return records, nil
}

// lookUp returns the lookup of userID that is under way or still served, or
// starts one.
func (s *SharedPublicKeys) lookUp(userID string) *publicKeyLookup {
	s.mu.Lock()
	defer s.mu.Unlock()
	at := s.now()
	if cached, ok := s.lookups[userID]; ok && cached.expires.After(at) {
		return cached
	}
	// Answers past their time go here, so the cache holds no more than the
	// users looked up within one TTL.
	for id, lookup := range s.lookups {
		if !lookup.expires.After(at) {
			delete(s.lookups, id)
		}
	}
	lookup := &publicKeyLookup{expires: at.Add(s.ttl), done: make(chan struct{})}
	s.lookups[userID] = lookup
	go s.run(userID, lookup)
	return lookup
}

// run fetches the records of userID and completes lookup with them. A fetch
// that fails takes lookup out of the cache before the callers waiting for it
// go on, so the next call for the user fetches again.
func (s *SharedPublicKeys) run(userID string, lookup *publicKeyLookup) {
	defer close(lookup.done)
	records, err := s.fetch(userID)
	if err != nil {
		s.mu.Lock()
		if s.lookups[userID] == lookup {
			delete(s.lookups, userID)
		}
		s.mu.Unlock()
		log.Printf("public_keys_fetch_failed user=%s err=%v", userID, err)
		return
	}
	lookup.found, lookup.records = true, records
}

// UserChats keeps one ChatCore per signed-in user, all fetching public keys
// through one hook. It may be used from several goroutines at once.
type UserChats struct {
	resolve func(userIDs []string) (map[string][]chatxdk.PublicKeyRecord, error)

	// mu guards chats.
	mu    sync.Mutex
	chats map[string]*ChatCore
}

// NewUserChats returns a UserChats with no chat yet. resolve is the hook
// every chat shares: the Resolve method of one SharedPublicKeys.
func NewUserChats(resolve func(userIDs []string) (map[string][]chatxdk.PublicKeyRecord, error)) *UserChats {
	return &UserChats{resolve: resolve, chats: map[string]*ChatCore{}}
}

// ChatFor returns the chat of the signed-in user userID, created on first
// use from the user's private-key blob and the public_key_version it was
// registered under. Calls for one user get the same chat, also from several
// goroutines, and that chat serves every conversation of the user.
func (u *UserChats) ChatFor(userID, privateKeysB64, signingKeyVersion string) (*ChatCore, error) {
	// Creating a chat waits for no request, so the lock is held meanwhile: a
	// call for the same user made at the same time gets the same chat.
	u.mu.Lock()
	defer u.mu.Unlock()
	if core, ok := u.chats[userID]; ok {
		return core, nil
	}
	core := NewChatCore()
	err := core.LoadKeys(privateKeysB64, signingKeyVersion)
	if err == nil {
		err = core.SetIdentity(userID)
	}
	if err != nil {
		// A chat that could not be created is not kept: the next call tries
		// again.
		core.Close()
		return nil, err
	}
	core.ResolvePublicKeysWith(u.resolve)
	u.chats[userID] = core
	return core, nil
}

// Close signs userID out: it forgets the user's chat and releases it. Call
// it when no call on that chat is under way; the chat must not be used
// afterwards.
func (u *UserChats) Close(userID string) {
	u.mu.Lock()
	core, ok := u.chats[userID]
	delete(u.chats, userID)
	u.mu.Unlock()
	if ok {
		core.Close()
	}
}
