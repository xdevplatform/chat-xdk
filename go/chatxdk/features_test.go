package chatxdk

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// offlineFeatures is an endpoint nothing listens on: a chat no test points at
// a server of its own fetches from it, fails, and stays on v0.
const offlineFeatures = "http://127.0.0.1:9/2/chat/features"

const driverHelperEnv = "CHATXDK_FEATURE_DRIVER_HELPER"

func TestMain(m *testing.M) {
	if err := ffiFeatureSetDefaultEndpoint(offlineFeatures); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

// configureFeatures points this chat's feature fetch at endpoint, with these
// timings; for tests only.
func (c *Chat) configureFeatures(endpoint string, timeout, recheck, firstRetry time.Duration) error {
	defer runtime.KeepAlive(c)
	return ffiFeatureConfigure(c.h, endpoint, timeout, recheck, firstRetry)
}

var (
	v1ServerOnce sync.Once
	v1Server     *httptest.Server
)

// enableV1Send turns v1_send on for chat as the X API would: it points the
// chat's feature fetch at a local server that answers it, then sends until a
// send is v1.
func enableV1Send(t *testing.T, chat *Chat) {
	t.Helper()
	v1ServerOnce.Do(func() {
		v1Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"features":{"v1_send":true}}`))
		}))
	})
	if err := chat.configureFeatures(v1Server.URL, 2*time.Second, time.Hour, 50*time.Millisecond); err != nil {
		t.Fatalf("configureFeatures failed: %v", err)
	}
	params := EncryptMessageParams{
		SenderID:               "1",
		ConversationID:         "feature-switches",
		Text:                   "turn v1 on",
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
// bucket.
type featureServer struct {
	*httptest.Server
	id      int64
	mu      sync.Mutex
	status  int
	body    string
	delay   time.Duration
	buckets []string
}

func newFeatureServer(t *testing.T) *featureServer {
	t.Helper()
	s := &featureServer{id: featureServerIDs.Add(1), status: http.StatusOK, body: `{"features":{"v1_send":true}}`}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The answer is fixed when the request is recorded, so a test that
		// sees the request can change the next answer.
		s.mu.Lock()
		s.buckets = append(s.buckets, r.URL.Query().Get("bucket"))
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

// featureServerIDs give each server an endpoint of its own: the core reuses an
// answer per endpoint and bucket for 5 minutes, and a server can get the port
// of one that came before it.
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
	return append([]string(nil), s.buckets...)
}

// featureTimings are a chat's request timeout, re-check interval and first
// retry delay.
type featureTimings struct {
	timeout, recheck, firstRetry time.Duration
}

var defaultTestTimings = featureTimings{2 * time.Second, time.Hour, 50 * time.Millisecond}

// featureChat is a keyed chat whose feature fetch goes to endpoint.
func featureChat(t *testing.T, v sdkVectors, endpoint string, timings featureTimings) *Chat {
	t.Helper()
	chat := New()
	if chat == nil {
		t.Fatal("New returned nil")
	}
	t.Cleanup(chat.Close)
	if err := chat.configureFeatures(endpoint, timings.timeout, timings.recheck, timings.firstRetry); err != nil {
		t.Fatalf("configureFeatures failed: %v", err)
	}
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
	waitForWithin(t, what, 10*time.Second, cond)
}

func waitForWithin(t *testing.T, what string, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
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

func TestNoRequestIsMadeUntilTheFirstSend(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	chat := featureChat(t, v, server.endpoint(), defaultTestTimings)
	time.Sleep(300 * time.Millisecond)
	if got := server.seen(); len(got) != 0 {
		t.Fatalf("requests before a send: %v", got)
	}

	if got := sendVersion(t, chat, v); got != "7" {
		t.Fatalf("first send is %q, want 7: it does not wait for the answer", got)
	}
	waitFor(t, "the request", func() bool { return len(server.seen()) == 1 })
	bucket, err := strconv.Atoi(server.seen()[0])
	if err != nil || bucket < 0 || bucket >= 10000 {
		t.Fatalf("bucket %q", server.seen()[0])
	}
}

func TestV1StartsOnceTheAnswerTurnsItOn(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	chat := featureChat(t, v, server.endpoint(), defaultTestTimings)
	if got := sendVersion(t, chat, v); got != "7" {
		t.Fatalf("first send is %q, want 7", got)
	}
	waitFor(t, "v1", func() bool { return sendVersion(t, chat, v) == "10" })
	if got := server.seen(); len(got) != 1 {
		t.Fatalf("requests: %v", got)
	}
}

func TestASendNeverWaitsForTheRequest(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	server.setDelay(2 * time.Second)
	chat := featureChat(t, v, server.endpoint(), defaultTestTimings)
	started := time.Now()
	if got := sendVersion(t, chat, v); got != "7" {
		t.Fatalf("send is %q, want 7", got)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("the send took %v", elapsed)
	}
}

func TestChatsWithOneKeyShareOneRequest(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	server.setDelay(300 * time.Millisecond)
	var chats []*Chat
	for i := 0; i < 4; i++ {
		chat := featureChat(t, v, server.endpoint(), defaultTestTimings)
		if got := sendVersion(t, chat, v); got != "7" {
			t.Fatalf("send is %q, want 7", got)
		}
		chats = append(chats, chat)
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
		t.Fatalf("requests: %v", got)
	}

	later := featureChat(t, v, server.endpoint(), defaultTestTimings)
	if got := sendVersion(t, later, v); got != "10" {
		t.Fatalf("a later chat sends %q, want 10: it takes the answer at hand", got)
	}
	if got := server.seen(); len(got) != 1 {
		t.Fatalf("requests: %v", got)
	}
}

func TestChatsWithDifferentKeysAskSeparately(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	first := featureChat(t, v, server.endpoint(), defaultTestTimings)
	second := featureChat(t, v, server.endpoint(), defaultTestTimings)
	other := New()
	defer other.Close()
	if _, err := other.GenerateKeypairs(); err != nil {
		t.Fatalf("GenerateKeypairs failed: %v", err)
	}
	keys, err := other.ExportKeys()
	if err != nil {
		t.Fatalf("ExportKeys failed: %v", err)
	}
	if err := second.ImportKeys(ImportKeysParams{Keys: keys}); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}
	if err := second.SetIdentity(SetIdentityParams{UserID: v.EventSenderID, SigningKeyVersion: v.EventSigningKeyVersion}); err != nil {
		t.Fatalf("SetIdentity failed: %v", err)
	}
	sendVersion(t, first, v)
	sendVersion(t, second, v)
	waitFor(t, "two requests", func() bool { return len(server.seen()) == 2 })
	if got := server.seen(); got[0] == got[1] {
		t.Fatalf("both requests carry bucket %s", got[0])
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
			// A server of its own: chats share an answer per endpoint and
			// bucket, and the case before may have left one.
			server := newFeatureServer(t)
			server.set(c.status, c.body)
			server.setDelay(c.delay)
			chat := featureChat(t, v, server.endpoint(), featureTimings{500 * time.Millisecond, time.Hour, time.Minute})
			if got := sendVersion(t, chat, v); got != "7" {
				t.Fatalf("send is %q, want 7", got)
			}
			waitFor(t, "the request", func() bool { return len(server.seen()) == 1 })
			if c.delay > 0 {
				time.Sleep(1200 * time.Millisecond)
			} else {
				time.Sleep(200 * time.Millisecond)
			}
			if got := sendVersion(t, chat, v); got != "7" {
				t.Fatalf("send is %q, want 7", got)
			}
		})
	}
}

func TestAnUnreachableEndpointLeavesSendsOnV0(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	endpoint := server.endpoint()
	server.Close()
	chat := featureChat(t, v, endpoint, featureTimings{500 * time.Millisecond, time.Hour, 50 * time.Millisecond})
	if got := sendVersion(t, chat, v); got != "7" {
		t.Fatalf("send is %q, want 7", got)
	}
	time.Sleep(500 * time.Millisecond)
	if got := sendVersion(t, chat, v); got != "7" {
		t.Fatalf("send is %q, want 7", got)
	}
}

func TestARequestStillOpenAtItsTimeoutFailsAndIsRetried(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	server.setDelay(3 * time.Second)
	chat := featureChat(t, v, server.endpoint(), featureTimings{300 * time.Millisecond, time.Hour, 200 * time.Millisecond})
	if got := sendVersion(t, chat, v); got != "7" {
		t.Fatalf("send is %q, want 7", got)
	}
	waitForWithin(t, "a retry", 2500*time.Millisecond, func() bool { return len(server.seen()) >= 2 })
	if got := sendVersion(t, chat, v); got != "7" {
		t.Fatalf("send is %q, want 7", got)
	}
}

func TestTheRecheckTurnsV1OffAndNeverBackOn(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	rechecking := featureTimings{2 * time.Second, 300 * time.Millisecond, 50 * time.Millisecond}
	chat := featureChat(t, v, server.endpoint(), rechecking)
	sendVersion(t, chat, v)
	waitFor(t, "v1", func() bool { return sendVersion(t, chat, v) == "10" })

	server.set(http.StatusOK, `{"features":{}}`)
	waitFor(t, "the re-check to turn v1 off", func() bool { return sendVersion(t, chat, v) == "7" })

	server.set(http.StatusOK, `{"features":{"v1_send":true}}`)
	seen := len(server.seen())
	waitFor(t, "two more re-checks", func() bool { return len(server.seen()) >= seen+2 })
	if got := sendVersion(t, chat, v); got != "7" {
		t.Fatalf("a running chat sends %q, want 7: it never sees v1 turn on", got)
	}
	later := featureChat(t, v, server.endpoint(), rechecking)
	if got := sendVersion(t, later, v); got != "10" {
		t.Fatalf("a new chat sends %q, want 10: it takes the latest answer", got)
	}
}

func TestAFailedRecheckChangesNothing(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	chat := featureChat(t, v, server.endpoint(), featureTimings{2 * time.Second, 300 * time.Millisecond, 50 * time.Millisecond})
	sendVersion(t, chat, v)
	waitFor(t, "v1", func() bool { return sendVersion(t, chat, v) == "10" })
	server.set(http.StatusServiceUnavailable, "")
	seen := len(server.seen())
	waitFor(t, "two failed re-checks", func() bool { return len(server.seen()) >= seen+2 })
	if got := sendVersion(t, chat, v); got != "10" {
		t.Fatalf("send is %q, want 10", got)
	}
}

func TestCloseStopsTheRequests(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	chat := featureChat(t, v, server.endpoint(), featureTimings{2 * time.Second, 300 * time.Millisecond, 50 * time.Millisecond})
	sendVersion(t, chat, v)
	waitFor(t, "v1", func() bool { return sendVersion(t, chat, v) == "10" })
	chat.Close()
	seen := len(server.seen())
	time.Sleep(time.Second)
	if got := len(server.seen()); got != seen {
		t.Fatalf("%d requests after Close", got-seen)
	}
}

// startUnreferencedChat leaves a re-checking chat that nothing references.
func startUnreferencedChat(t *testing.T, v sdkVectors, endpoint string) {
	chat := New()
	if err := chat.configureFeatures(endpoint, 2*time.Second, 300*time.Millisecond, 50*time.Millisecond); err != nil {
		t.Fatalf("configureFeatures failed: %v", err)
	}
	if err := chat.ImportKeys(ImportKeysParams{Keys: v.privateKeys(t)}); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}
	if err := chat.SetIdentity(SetIdentityParams{UserID: v.EventSenderID, SigningKeyVersion: v.EventSigningKeyVersion}); err != nil {
		t.Fatalf("SetIdentity failed: %v", err)
	}
	sendVersion(t, chat, v)
	waitFor(t, "v1", func() bool { return sendVersion(t, chat, v) == "10" })
}

func TestTheRequestsEndWithAnUnreferencedChat(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	startUnreferencedChat(t, v, server.endpoint())
	running := len(server.seen())
	waitFor(t, "a re-check", func() bool { return len(server.seen()) > running })
	for i := 0; i < 5; i++ {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(800 * time.Millisecond)
	seen := len(server.seen())
	time.Sleep(1200 * time.Millisecond)
	if got := len(server.seen()); got != seen {
		t.Fatalf("%d requests once the chat was collected", got-seen)
	}
}

// featureDrivers counts the goroutines running featureDriver.
func featureDrivers() int {
	buf := make([]byte, 1<<20)
	return strings.Count(string(buf[:runtime.Stack(buf, true)]), "chatxdk.featureDriver(")
}

// TestTheDriverEndsWithTheLastChat runs in a process of its own, so no chat of
// another test keeps the driver running.
func TestTheDriverEndsWithTheLastChat(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestFeatureDriverHelper$", "-test.v")
	cmd.Env = append(os.Environ(), driverHelperEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "PASS") {
		t.Fatalf("helper process failed: %v\n%s", err, out)
	}
}

func TestFeatureDriverHelper(t *testing.T) {
	if os.Getenv(driverHelperEnv) != "1" {
		t.Skip("run by TestTheDriverEndsWithTheLastChat")
	}
	v := loadVectors(t)
	server := newFeatureServer(t)
	if n := featureDrivers(); n != 0 {
		t.Fatalf("%d drivers before a send", n)
	}
	var chats []*Chat
	for i := 0; i < 3; i++ {
		chat := New()
		if err := chat.configureFeatures(server.endpoint(), 2*time.Second, 300*time.Millisecond, 50*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if err := chat.ImportKeys(ImportKeysParams{Keys: v.privateKeys(t)}); err != nil {
			t.Fatal(err)
		}
		if err := chat.SetIdentity(SetIdentityParams{UserID: v.EventSenderID, SigningKeyVersion: v.EventSigningKeyVersion}); err != nil {
			t.Fatal(err)
		}
		chats = append(chats, chat)
	}
	for _, chat := range chats {
		sendVersion(t, chat, v)
	}
	waitFor(t, "v1 everywhere", func() bool {
		return !slices.ContainsFunc(chats, func(c *Chat) bool { return sendVersion(t, c, v) != "10" })
	})
	if n := featureDrivers(); n != 1 {
		t.Fatalf("%d drivers, want 1", n)
	}
	waitFor(t, "re-checks while chats remain", func() bool { return len(server.seen()) >= 3 })

	for _, chat := range chats {
		chat.Close()
	}
	waitForWithin(t, "the driver to end", 3*time.Second, func() bool { return featureDrivers() == 0 })
	seen := len(server.seen())
	time.Sleep(time.Second)
	if got := len(server.seen()); got != seen {
		t.Fatalf("%d requests once no chat remains", got-seen)
	}
}
