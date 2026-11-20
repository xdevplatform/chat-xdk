package main

import (
	"log"
	"time"

	"github.com/xdevplatform/chat-xdk/go/chatxdk"
)

// generateReply turns an incoming message into a reply (a simple echo).
func generateReply(text string) string {
	switch text {
	case "ping", "!ping":
		return "pong"
	default:
		return "You said: " + text
	}
}

// conversationState holds the in-memory state for one conversation. The
// conversation keys themselves live in the SDK's opt-in key cache, filled by
// the batch decrypt path.
type conversationState struct {
	seenEventIDs    map[string]bool
	paginationToken string
}

func newConversationState() *conversationState {
	return &conversationState{seenEventIDs: map[string]bool{}}
}

// Bot wires the crypto core to the X Chat API and runs the reply loop.
//
// One Bot serves one signed-in user, in any number of conversations. A
// process with several signed-in users keeps one chat per user and gives
// each the same public-key resolver: see multiuser.go.
type Bot struct {
	core      *ChatCore
	api       *XChatClient
	botUserID string
	state     map[string]*conversationState
}

// NewBot sets the bot's session identity and has the SDK fetch the public
// keys it lacks through the API client: the signing keys that verify a
// page's events, and the identity keys a key change is encrypted to.
func NewBot(core *ChatCore, api *XChatClient, botUserID string) *Bot {
	if err := core.SetIdentity(botUserID); err != nil {
		log.Printf("set_identity_failed err=%v", err)
	}
	core.FetchPublicKeysWith(api.GetPublicKeys)
	return &Bot{
		core:      core,
		api:       api,
		botUserID: botUserID,
		state:     map[string]*conversationState{},
	}
}

func (b *Bot) stateFor(conversationID string) *conversationState {
	st, ok := b.state[conversationID]
	if !ok {
		st = newConversationState()
		b.state[conversationID] = st
	}
	return st
}

// decryptPage batch-decrypts one page of events and logs what the batch
// could not use.
//
// The key events go into the same batch as the data events: they are the
// only source of the conversation keys the messages decrypt under. The SDK
// fetches the public keys the page lacks, those of the members who made its
// key changes as well as those of the senders of its messages, and caches
// the key of each key change that verifies.
func (b *Bot) decryptPage(conversationID string, events []EventItem, keyEvents []string) (*chatxdk.DecryptEventsResult, error) {
	eventsB64 := append([]string{}, keyEvents...)
	for _, e := range events {
		if e.EncodedEvent != "" {
			eventsB64 = append(eventsB64, e.EncodedEvent)
		}
	}
	result, err := b.core.DecryptBatch(eventsB64)
	if err != nil {
		return nil, err
	}
	for index, key := range result.MissingSigningKeys {
		log.Printf("signing_key_missing conv=%s event=%s user=%s version=%s",
			conversationID, index, key.UserID, key.PublicKeyVersion)
	}
	for index, change := range result.UnverifiedKeyChanges {
		signer := ""
		if change.SenderID != nil {
			signer = *change.SenderID
		}
		log.Printf("key_change_unverified conv=%s event=%s reason=%s signer=%s key_dropped=%t",
			conversationID, index, change.Reason, signer, change.KeyDropped)
	}
	for index, change := range result.UndecryptableKeyChanges {
		log.Printf("key_change_undecryptable conv=%s event=%s reason=%s", conversationID, index, change.Reason)
	}
	for index, key := range result.RejectedSigningKeys {
		log.Printf("signing_key_rejected index=%s user=%s version=%s", index, key.UserID, key.PublicKeyVersion)
	}
	return result, nil
}

// LoadBacklog batch-decrypts the conversation backlog (DecryptEvents path),
// filling the SDK's conversation-key cache from the KeyChange events.
func (b *Bot) LoadBacklog(conversationID string) error {
	st := b.stateFor(conversationID)
	events, keyEvents, next, err := b.api.GetEvents(conversationID, 100, "")
	if err != nil {
		return err
	}
	result, err := b.decryptPage(conversationID, events, keyEvents)
	if err != nil {
		return err
	}
	st.paginationToken = next
	log.Printf("backlog_loaded conv=%s messages=%d keys=%d", conversationID, len(result.Events), len(result.ConversationKeys.Keys))
	return nil
}

// PollOnce fetches the next page of events, batch-decrypts it, and replies
// to its messages.
func (b *Bot) PollOnce(conversationID string) error {
	st := b.stateFor(conversationID)
	events, keyEvents, next, err := b.api.GetEvents(conversationID, 50, st.paginationToken)
	if err != nil {
		return err
	}
	result, err := b.decryptPage(conversationID, events, keyEvents)
	if err != nil {
		return err
	}
	for index, reason := range result.Errors {
		log.Printf("decrypt_failed conv=%s event=%s err=%s", conversationID, index, reason)
	}
	for i := range result.Events {
		decrypted := &result.Events[i]
		// A reply is threaded under the raw event of its message.
		if decrypted.OriginalB64 != "" {
			b.maybeReply(conversationID, decrypted.OriginalB64, &decrypted.Event)
		}
	}
	if next != "" {
		st.paginationToken = next
	}
	return nil
}

// maybeReply answers a decrypted message with a threaded reply anchored on
// the raw incoming event.
func (b *Bot) maybeReply(conversationID, rawEventB64 string, event *chatxdk.Event) {
	st := b.stateFor(conversationID)
	msg := event.AsMessage()
	if msg == nil {
		return
	}
	eventID := ""
	if msg.ID != nil {
		eventID = *msg.ID
	}
	senderID := ""
	if msg.SenderID != nil {
		senderID = *msg.SenderID
	}
	if eventID == "" || st.seenEventIDs[eventID] {
		return
	}
	st.seenEventIDs[eventID] = true
	if senderID == b.botUserID {
		return
	}
	text := msg.Text()
	if text == "" {
		return
	}

	// The message signature covers the conversation_id, so sign with the
	// canonical id carried inside the event (the X API uses a different
	// separator in its URL paths than the form embedded in events).
	replyConvID := conversationID
	if msg.ConversationID != nil && *msg.ConversationID != "" {
		replyConvID = *msg.ConversationID
	}
	reply := generateReply(text)
	// Reply by raw event: the SDK derives the preview from it, and the
	// conversation key resolves from the key cache.
	body, err := b.core.EncryptReply(replyConvID, reply, &ReplyOptions{ReplyToEvent: rawEventB64})
	if err != nil {
		log.Printf("encrypt_failed conv=%s err=%v", replyConvID, err)
		return
	}
	if err := b.api.SendMessage(replyConvID, body); err != nil {
		log.Printf("send_failed conv=%s err=%v", replyConvID, err)
		return
	}
	log.Printf("reply_sent conv=%s len=%d", replyConvID, len(reply))
}

// Run loads the backlog then polls forever.
func (b *Bot) Run(conversationID string, pollInterval time.Duration) error {
	if err := b.LoadBacklog(conversationID); err != nil {
		return err
	}
	log.Printf("bot_running conv=%s polling every %s", conversationID, pollInterval)
	for {
		if err := b.PollOnce(conversationID); err != nil {
			log.Printf("poll_error conv=%s err=%v", conversationID, err)
		}
		time.Sleep(pollInterval)
	}
}
