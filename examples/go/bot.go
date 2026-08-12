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
type Bot struct {
	core      *ChatCore
	api       *XChatClient
	botUserID string
	state     map[string]*conversationState
	// signingKeys accumulates every sender's keys; the merged set is stored
	// in the SDK via SetSigningKeys so decrypt calls can pass nil.
	signingKeys []chatxdk.SigningKeyEntry
	seenSenders map[string]bool
}

func NewBot(core *ChatCore, api *XChatClient, botUserID string) *Bot {
	if err := core.SetIdentity(botUserID); err != nil {
		log.Printf("set_identity_failed err=%v", err)
	}
	return &Bot{
		core:        core,
		api:         api,
		botUserID:   botUserID,
		state:       map[string]*conversationState{},
		seenSenders: map[string]bool{},
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

// refreshSigningKeys fetches public keys for senders not seen before and
// stores the merged set in the SDK, so decrypt calls verify against it.
func (b *Bot) refreshSigningKeys(events []EventItem) {
	added := false
	for _, e := range events {
		if e.SenderID == "" || e.SenderID == b.botUserID || b.seenSenders[e.SenderID] {
			continue
		}
		b.seenSenders[e.SenderID] = true
		pks, err := b.api.GetPublicKeys(e.SenderID)
		if err != nil {
			log.Printf("public_keys_fetch_failed sender=%s err=%v", e.SenderID, err)
			continue
		}
		for _, pk := range pks {
			b.signingKeys = append(b.signingKeys, chatxdk.SigningKeyEntry{
				UserID:                     e.SenderID,
				PublicKeyVersion:           str(pk["public_key_version"]),
				PublicKey:                  str(pk["signing_public_key"]),
				IdentityPublicKey:          str(pk["public_key"]),
				IdentityPublicKeySignature: str(pk["identity_public_key_signature"]),
			})
			added = true
		}
	}
	if added {
		if err := b.core.SetSigningKeys(b.signingKeys); err != nil {
			log.Printf("set_signing_keys_failed err=%v", err)
		}
	}
}

// LoadBacklog batch-decrypts the conversation backlog (DecryptEvents path),
// filling the SDK's conversation-key cache from the KeyChange events.
func (b *Bot) LoadBacklog(conversationID string) error {
	st := b.stateFor(conversationID)
	events, keyEvents, next, err := b.api.GetEvents(conversationID, 100, "")
	if err != nil {
		return err
	}
	b.refreshSigningKeys(events)
	// The key events must be in the same batch as the messages: they are the
	// only source of the conversation keys the messages decrypt under.
	eventsB64 := append([]string{}, keyEvents...)
	for _, e := range events {
		if e.EncodedEvent != "" {
			eventsB64 = append(eventsB64, e.EncodedEvent)
		}
	}
	result, err := b.core.DecryptBatch(eventsB64, nil)
	if err != nil {
		return err
	}
	st.paginationToken = next
	log.Printf("backlog_loaded conv=%s messages=%d keys=%d", conversationID, len(result.Messages), len(result.ConversationKeys.Keys))
	return nil
}

// PollOnce fetches new events and replies using the single-event decrypt path.
func (b *Bot) PollOnce(conversationID string) error {
	st := b.stateFor(conversationID)
	events, keyEvents, next, err := b.api.GetEvents(conversationID, 50, st.paginationToken)
	if err != nil {
		return err
	}
	b.refreshSigningKeys(events)
	// Key changes for this page arrive in meta, not data; only the batch
	// path feeds the key cache, so route them through it before decrypting.
	// This runs after the signing-key refresh: a key change from a sender not
	// yet in the store would fail verification and never be cached.
	if len(keyEvents) > 0 {
		if _, err := b.core.DecryptBatch(keyEvents, nil); err != nil {
			log.Printf("key_events_decrypt_failed conv=%s err=%v", conversationID, err)
		}
	}
	for _, item := range events {
		if item.EncodedEvent == "" {
			continue
		}
		// nil maps: conversation keys come from the SDK's cache, signing
		// keys from the stored set.
		event, err := b.core.DecryptOne(item.EncodedEvent, nil, nil)
		if err != nil {
			log.Printf("decrypt_failed conv=%s err=%v", conversationID, err)
			continue
		}
		if event.AsKeyChange() != nil {
			// Only the batch path adopts keys into the SDK's cache; replay
			// the key change through it so the rotated key becomes the
			// sending key.
			if _, err := b.core.DecryptBatch([]string{item.EncodedEvent}, nil); err != nil {
				log.Printf("key_adopt_failed conv=%s err=%v", conversationID, err)
			}
			continue
		}
		b.maybeReply(conversationID, item.EncodedEvent, event)
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

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
