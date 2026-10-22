package chatxdk

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// offlineFeatures is an endpoint nothing listens on: a chat no test points at
// a server of its own reads from it, fails, and stays on v0.
const offlineFeatures = "http://127.0.0.1:9/2/chat/features"

func TestMain(m *testing.M) {
	if err := ffiFeatureSetDefaultEndpoint(offlineFeatures); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

// newChatReading is a chat that reads its feature switches from endpoint,
// within timeout; for tests only.
func newChatReading(t *testing.T, endpoint string, timeout time.Duration) *Chat {
	t.Helper()
	chat := newChat()
	if chat == nil {
		t.Fatal("newChat returned nil")
	}
	if err := ffiFeatureConfigure(chat.h, endpoint, timeout); err != nil {
		chat.Close()
		t.Fatalf("ffiFeatureConfigure failed: %v", err)
	}
	chat.startFeatures()
	return chat
}

var (
	v1ServerOnce sync.Once
	v1Server     *httptest.Server
)

// newV1Chat is a chat whose feature switches turn v1_send on, as the X API
// would: it reads them from a local server that answers so. waitForV1 waits
// for the answer.
func newV1Chat(t *testing.T) *Chat {
	t.Helper()
	v1ServerOnce.Do(func() {
		v1Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"features":{"v1_send":true}}`))
		}))
	})
	return newChatReading(t, v1Server.URL, 2*time.Second)
}

// waitForV1 sends from chat, which has keys, until a send is v1.
func waitForV1(t *testing.T, chat *Chat) {
	t.Helper()
	params := EncryptMessageParams{
		SenderID:               "1",
		ConversationID:         "feature-switches",
		Text:                   "wait for v1",
		ConversationKey:        make([]byte, 32),
		ConversationKeyVersion: "1",
		SigningKeyVersion:      "1",
	}
	waitFor(t, "v1_send on", func() bool {
		payload, err := chat.EncryptMessage(params)
		if err != nil {
			t.Fatalf("EncryptMessage failed: %v", err)
		}
		return payload.SignatureInfo.SignatureVersion == "10"
	})
}

// featureServer is a local GET /2/chat/features that records each request's
// query string.
type featureServer struct {
	*httptest.Server
	id      int64
	mu      sync.Mutex
	status  int
	body    string
	delay   time.Duration
	queries []string
}

func newFeatureServer(t *testing.T) *featureServer {
	t.Helper()
	s := &featureServer{id: featureServerIDs.Add(1), status: http.StatusOK, body: `{"features":{"v1_send":true}}`}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The answer is fixed when the request is recorded, so a test that
		// sees the request can change the next answer.
		s.mu.Lock()
		s.queries = append(s.queries, r.URL.RawQuery)
		status, body, delay := s.status, s.body, s.delay
		s.mu.Unlock()
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

// featureServerIDs give each server an endpoint of its own: chats created
// while a GET for their endpoint is in flight share it, and a server can get
// the port of one that came before it.
var featureServerIDs atomic.Int64

func (s *featureServer) endpoint() string {
	return s.URL + "/" + strconv.FormatInt(s.id, 10) + "/2/chat/features"
}

func (s *featureServer) set(status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.body = status, body
}

func (s *featureServer) setDelay(delay time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delay = delay
}

func (s *featureServer) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.queries...)
}

// featureChat is a keyed chat that reads its feature switches from endpoint,
// within timeout.
func featureChat(t *testing.T, v sdkVectors, endpoint string, timeout time.Duration) *Chat {
	t.Helper()
	chat := newChatReading(t, endpoint, timeout)
	t.Cleanup(chat.Close)
	if err := chat.ImportKeys(ImportKeysParams{Keys: v.privateKeys(t)}); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}
	if err := chat.SetIdentity(SetIdentityParams{UserID: v.EventSenderID, SigningKeyVersion: v.EventSigningKeyVersion}); err != nil {
		t.Fatalf("SetIdentity failed: %v", err)
	}
	return chat
}

// sendVersion is the signature version of a send: "7" for v0, "10" for v1.
func sendVersion(t *testing.T, chat *Chat, v sdkVectors) string {
	t.Helper()
	payload, err := chat.EncryptMessage(EncryptMessageParams{
		ConversationID:         v.EventConversationID,
		Text:                   "hello",
		ConversationKey:        v.conversationKey(t),
		ConversationKeyVersion: v.EventConversationKeyVersion,
	})
	if err != nil {
		t.Fatalf("EncryptMessage failed: %v", err)
	}
	return payload.SignatureInfo.SignatureVersion
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestFeatureSwitchesAreNotPublicAPI(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var declared []string
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				declared = append(declared, n.Name.Name)
			case *ast.TypeSpec:
				declared = append(declared, n.Name.Name)
			case *ast.ValueSpec:
				for _, id := range n.Names {
					declared = append(declared, id.Name)
				}
			}
			return true
		})
	}
	for _, name := range declared {
		if token.IsExported(name) && strings.Contains(strings.ToLower(name), "feature") {
			t.Errorf("%s is exported", name)
		}
	}
}

func TestANewChatReadsTheSwitchesOnce(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	chat := featureChat(t, v, server.endpoint(), 2*time.Second)
	waitFor(t, "the request", func() bool { return len(server.seen()) == 1 })
	if got := server.seen()[0]; got != "" {
		t.Fatalf("query %q, want none", got)
	}
	waitFor(t, "v1", func() bool { return sendVersion(t, chat, v) == "10" })
	if err := chat.ImportKeys(ImportKeysParams{Keys: v.privateKeys(t)}); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}
	if err := chat.SetIdentity(SetIdentityParams{UserID: v.EventSenderID, SigningKeyVersion: v.EventSigningKeyVersion}); err != nil {
		t.Fatalf("SetIdentity failed: %v", err)
	}
	for i := 0; i < 5; i++ {
		sendVersion(t, chat, v)
	}
	time.Sleep(300 * time.Millisecond)
	if got := server.seen(); len(got) != 1 {
		t.Fatalf("requests: %d, want 1", len(got))
	}
}

func TestNewReadsTheDefaultEndpoint(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	if err := ffiFeatureSetDefaultEndpoint(server.endpoint()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ffiFeatureSetDefaultEndpoint(offlineFeatures); err != nil {
			t.Fatal(err)
		}
	})
	chat := New()
	t.Cleanup(chat.Close)
	waitFor(t, "the request", func() bool { return len(server.seen()) == 1 })
	if err := chat.ImportKeys(ImportKeysParams{Keys: v.privateKeys(t)}); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}
	if err := chat.SetIdentity(SetIdentityParams{UserID: v.EventSenderID, SigningKeyVersion: v.EventSigningKeyVersion}); err != nil {
		t.Fatalf("SetIdentity failed: %v", err)
	}
	waitFor(t, "v1", func() bool { return sendVersion(t, chat, v) == "10" })
}

func TestASendNeverWaitsForTheRequest(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	server.setDelay(2 * time.Second)
	chat := featureChat(t, v, server.endpoint(), 3*time.Second)
	started := time.Now()
	if got := sendVersion(t, chat, v); got != "7" {
		t.Fatalf("send is %q, want 7", got)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("the send took %v", elapsed)
	}
}

func TestChatsCreatedWhileARequestIsInFlightShareIt(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	server.setDelay(800 * time.Millisecond)
	var chats []*Chat
	for i := 0; i < 4; i++ {
		chats = append(chats, featureChat(t, v, server.endpoint(), 2*time.Second))
	}
	waitFor(t, "v1 everywhere", func() bool {
		for _, chat := range chats {
			if sendVersion(t, chat, v) != "10" {
				return false
			}
		}
		return true
	})
	if got := server.seen(); len(got) != 1 {
		t.Fatalf("requests: %d, want 1", len(got))
	}

	later := featureChat(t, v, server.endpoint(), 2*time.Second)
	waitFor(t, "the later chat's own request", func() bool { return len(server.seen()) == 2 })
	waitFor(t, "v1 for the later chat", func() bool { return sendVersion(t, later, v) == "10" })
}

func TestTheAnswerHoldsForTheChatsLifetime(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	chat := featureChat(t, v, server.endpoint(), 2*time.Second)
	waitFor(t, "v1", func() bool { return sendVersion(t, chat, v) == "10" })

	server.set(http.StatusOK, `{"features":{}}`)
	other := featureChat(t, v, server.endpoint(), 2*time.Second)
	waitFor(t, "the second request", func() bool { return len(server.seen()) == 2 })
	time.Sleep(200 * time.Millisecond)
	if got := sendVersion(t, other, v); got != "7" {
		t.Fatalf("the second chat sends %q, want 7: it reads its own answer", got)
	}
	if got := sendVersion(t, chat, v); got != "10" {
		t.Fatalf("the first chat sends %q, want 10: its answer holds", got)
	}
}

func TestAnyFailureLeavesSendsOnV0(t *testing.T) {
	v := loadVectors(t)
	cases := []struct {
		status int
		body   string
		delay  time.Duration
	}{
		{404, `{"features":{"v1_send":true}}`, 0},
		{500, `{"features":{"v1_send":true}}`, 0},
		{200, "not json", 0},
		{200, `{"v1_send":true}`, 0},
		{200, `{"features":{"v1_send":"true"}}`, 0},
		{200, `{"features":{"v1_send":true}}` + strings.Repeat(" ", 64*1024), 0},
		{200, `{"features":{"v1_send":true}}`, time.Second},
	}
	for _, c := range cases {
		t.Run(strconv.Itoa(c.status)+"/"+strconv.Itoa(len(c.body))+"/"+c.delay.String(), func(t *testing.T) {
			server := newFeatureServer(t)
			server.set(c.status, c.body)
			server.setDelay(c.delay)
			chat := featureChat(t, v, server.endpoint(), 500*time.Millisecond)
			waitFor(t, "the request", func() bool { return len(server.seen()) == 1 })
			time.Sleep(c.delay + 200*time.Millisecond)
			if got := sendVersion(t, chat, v); got != "7" {
				t.Fatalf("send is %q, want 7", got)
			}
			if got := server.seen(); len(got) != 1 {
				t.Fatalf("requests: %d, want 1: a failure is not retried", len(got))
			}
		})
	}
}

func TestAnUnreachableEndpointLeavesSendsOnV0(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	endpoint := server.endpoint()
	server.Close()
	chat := featureChat(t, v, endpoint, 500*time.Millisecond)
	time.Sleep(700 * time.Millisecond)
	if got := sendVersion(t, chat, v); got != "7" {
		t.Fatalf("send is %q, want 7", got)
	}
}

func TestARequestStillOpenAtItsTimeoutFails(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	server.setDelay(3 * time.Second)
	chat := featureChat(t, v, server.endpoint(), 300*time.Millisecond)
	time.Sleep(time.Second)
	if got := sendVersion(t, chat, v); got != "7" {
		t.Fatalf("send is %q, want 7", got)
	}
	if got := server.seen(); len(got) != 1 {
		t.Fatalf("requests: %d, want 1", len(got))
	}
}

// startUnreferencedChat leaves a chat that nothing references, with its
// request in flight.
func startUnreferencedChat(t *testing.T, endpoint string) {
	newChatReading(t, endpoint, 2*time.Second)
}

func TestARequestEndsSafelyForAClosedOrCollectedChat(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	server.setDelay(800 * time.Millisecond)
	closed := featureChat(t, v, server.endpoint(), 2*time.Second)
	closed.Close()
	startUnreferencedChat(t, server.endpoint())
	for i := 0; i < 5; i++ {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
	}
	kept := featureChat(t, v, server.endpoint(), 2*time.Second)
	waitFor(t, "v1 for the chat still open", func() bool { return sendVersion(t, kept, v) == "10" })
	if got := server.seen(); len(got) != 1 {
		t.Fatalf("requests: %d, want 1", len(got))
	}
}
