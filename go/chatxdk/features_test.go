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
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// Keep every chat's automatic feature fetch off the network unless a
	// test points it at its own server.
	if os.Getenv(featuresEndpointEnv) == "" {
		os.Setenv(featuresEndpointEnv, "http://127.0.0.1:9/2/chat/features")
	}
	os.Exit(m.Run())
}

// The flag accessors the feature goroutine drives, for tests only.

func (c *Chat) isEnabled(name string) bool {
	defer runtime.KeepAlive(c)
	return ffiIsEnabled(c.h, name) == 1
}

func (c *Chat) featureBucket() int {
	defer runtime.KeepAlive(c)
	return ffiFeatureBucket(c.h)
}

func (c *Chat) applyFeatureConfig(json string, bucket int, downgradeOnly bool) error {
	defer runtime.KeepAlive(c)
	return ffiApplyFeatureConfig(c.h, json, bucket, downgradeOnly)
}

func (c *Chat) featureRefetchDue() bool {
	defer runtime.KeepAlive(c)
	return ffiFeatureRefetchDue(c.h) == 1
}

func enableV1Send(t *testing.T, chat *Chat) {
	t.Helper()
	if err := chat.applyFeatureConfig(`{"features":{"v1_send":true}}`, chat.featureBucket(), false); err != nil {
		t.Fatalf("applyFeatureConfig failed: %v", err)
	}
}

// featureServer is a local GET /2/chat/features that records each request's
// bucket ("" when it carried none).
type featureServer struct {
	*httptest.Server
	mu      sync.Mutex
	status  int
	body    string
	delay   time.Duration
	buckets []string
}

func newFeatureServer(t *testing.T) *featureServer {
	t.Helper()
	s := &featureServer{status: http.StatusOK, body: `{"features":{"v1_send":true}}`}
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

func (s *featureServer) endpoint() string {
	return s.URL + "/2/chat/features"
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

// testFeatureOptions are shorter timings than New's (2 s, 300 s, 1 s).
func testFeatureOptions(endpoint string) featureOptions {
	return featureOptions{
		endpoint: endpoint,
		timeout:  500 * time.Millisecond,
		refresh:  time.Hour,
		keyPoll:  20 * time.Millisecond,
	}
}

func featureChat(t *testing.T, opts featureOptions) *Chat {
	t.Helper()
	chat := newChat(opts)
	if chat == nil {
		t.Fatal("newChat returned nil")
	}
	t.Cleanup(chat.Close)
	return chat
}

func importFeatureKeys(t *testing.T, chat *Chat, v sdkVectors) {
	t.Helper()
	if err := chat.ImportKeys(ImportKeysParams{Keys: v.privateKeys(t)}); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}
	if err := chat.SetIdentity(SetIdentityParams{UserID: v.EventSenderID, SigningKeyVersion: v.EventSigningKeyVersion}); err != nil {
		t.Fatalf("SetIdentity failed: %v", err)
	}
}

func sendVersion(t *testing.T, chat *Chat, v sdkVectors) *SendPayload {
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
	return payload
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

// keyedRequest waits for a request carrying the chat's key bucket.
func keyedRequest(t *testing.T, server *featureServer, chat *Chat) {
	t.Helper()
	bucket := strconv.Itoa(chat.featureBucket())
	waitFor(t, "a request with bucket "+bucket, func() bool { return slices.Contains(server.seen(), bucket) })
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
	for _, name := range []string{
		"FeaturesEndpoint", "FeatureV1Send", "LoadFeatureConfigParams", "LoadFeatureConfig",
		"IsEnabled", "FeatureBucket", "ApplyFeatureConfig", "FeatureRefetchDue",
	} {
		if slices.Contains(declared, name) {
			t.Errorf("%s is exported", name)
		}
	}
}

func TestCreatingAChatNeverWaitsForTheFetch(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	server.setDelay(2 * time.Second)
	opts := testFeatureOptions(server.endpoint())
	opts.timeout = 5 * time.Second
	start := time.Now()
	chat := featureChat(t, opts)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("creating a chat took %v", elapsed)
	}
	importFeatureKeys(t, chat, v)
	if got := sendVersion(t, chat, v).SignatureInfo.SignatureVersion; got != "7" {
		t.Errorf("signature version %q, want 7", got)
	}

	// New reads the endpoint from the environment hook.
	other := newFeatureServer(t)
	other.setDelay(2 * time.Second)
	t.Setenv(featuresEndpointEnv, other.endpoint())
	start = time.Now()
	created := New()
	defer created.Close()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("New took %v", elapsed)
	}
	waitFor(t, "New's request", func() bool { return len(other.seen()) == 1 })
}

func TestEveryFlagIsOffAndSendsAreV0UntilAResponseApplies(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	server.set(http.StatusServiceUnavailable, ``)
	chat := featureChat(t, testFeatureOptions(server.endpoint()))
	importFeatureKeys(t, chat, v)
	keyedRequest(t, server, chat)
	if chat.isEnabled("v1_send") {
		t.Fatal("v1_send on without a response")
	}
	payload := sendVersion(t, chat, v)
	if payload.SignatureInfo.SignatureVersion != "7" {
		t.Errorf("signature version %q, want 7", payload.SignatureInfo.SignatureVersion)
	}
	if payload.XdkVersion == "" {
		t.Error("expected xdk_version")
	}
}

func TestAChatFetchesOnCreationAndAgainWithTheKeyBucket(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	chat := featureChat(t, testFeatureOptions(server.endpoint()))
	if chat.featureBucket() != -1 {
		t.Fatal("bucket before keys")
	}
	waitFor(t, "the request on creation", func() bool { return len(server.seen()) == 1 })
	if got := server.seen(); got[0] != "" {
		t.Fatalf("buckets %v, want one bucketless request", got)
	}

	importFeatureKeys(t, chat, v)
	bucket := chat.featureBucket()
	if bucket < 0 || bucket >= 10000 {
		t.Fatalf("bucket %d out of range", bucket)
	}
	keyedRequest(t, server, chat)
	waitFor(t, "v1_send on", func() bool { return chat.isEnabled("v1_send") })
	if chat.featureRefetchDue() {
		t.Fatal("refetch still due")
	}
	if got := server.seen(); !slices.Equal(got, []string{"", strconv.Itoa(bucket)}) {
		t.Fatalf("buckets %v, want [\"\" %d]", got, bucket)
	}
	if got := sendVersion(t, chat, v).SignatureInfo.SignatureVersion; got != "10" {
		t.Errorf("signature version %q, want 10", got)
	}
}

func TestKeysLoadedBeforeTheFirstAnswerStillGetTheKeyBucket(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	server.setDelay(200 * time.Millisecond)
	chat := featureChat(t, testFeatureOptions(server.endpoint()))
	importFeatureKeys(t, chat, v)
	waitFor(t, "v1_send on", func() bool { return chat.isEnabled("v1_send") })
	got := server.seen()
	if want := strconv.Itoa(chat.featureBucket()); got[len(got)-1] != want {
		t.Fatalf("buckets %v, want the last one %s", got, want)
	}
}

func TestTheKeyBucketAnswerReplacesTheIPAnswer(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)

	// An IP-bucketed "on" reads off once keys load, and the key's own answer
	// decides.
	first := featureChat(t, testFeatureOptions(server.endpoint()))
	waitFor(t, "the IP answer", func() bool { return first.isEnabled("v1_send") })
	server.set(http.StatusOK, `{"features":{"v1_send":false}}`)
	importFeatureKeys(t, first, v)
	if first.isEnabled("v1_send") {
		t.Fatal("flags must read off until the key-bucketed refetch")
	}
	keyedRequest(t, server, first)
	waitFor(t, "the key answer", func() bool { return !first.featureRefetchDue() })
	if first.isEnabled("v1_send") {
		t.Fatal("the key answer was false")
	}

	// ...and the key's answer can turn a flag on that the IP answer left off.
	server.set(http.StatusOK, `{"features":{"v1_send":false,"ip_answer":true}}`)
	second := featureChat(t, testFeatureOptions(server.endpoint()))
	waitFor(t, "the IP answer", func() bool { return second.isEnabled("ip_answer") })
	server.set(http.StatusOK, `{"features":{"v1_send":true}}`)
	importFeatureKeys(t, second, v)
	waitFor(t, "the key answer", func() bool { return second.isEnabled("v1_send") })
	if second.isEnabled("ip_answer") {
		t.Fatal("the key answer did not replace the IP answer")
	}
}

func TestUnknownKeysAreReadableAndMissingKeysAreOff(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	server.set(http.StatusOK, `{"features":{"later_flag":true,"v1_send":"yes"},"extra":1}`)
	chat := featureChat(t, testFeatureOptions(server.endpoint()))
	importFeatureKeys(t, chat, v)
	waitFor(t, "later_flag on", func() bool { return chat.isEnabled("later_flag") })
	if chat.isEnabled("v1_send") || chat.isEnabled("missing") {
		t.Fatal("unexpected flag values")
	}
}

func TestAnyFailureLeavesEveryFlagOff(t *testing.T) {
	v := loadVectors(t)
	cases := []struct {
		status int
		body   string
		delay  time.Duration
	}{
		{http.StatusNotFound, `{"features":{"v1_send":true}}`, 0},
		{http.StatusInternalServerError, `{"features":{"v1_send":true}}`, 0},
		{http.StatusOK, `not json`, 0},
		{http.StatusOK, `{"v1_send":true}`, 0},
		{http.StatusOK, `{"features":{"v1_send":true}}`, 1500 * time.Millisecond},
		{http.StatusOK, `{"features":{"v1_send":true}}` + strings.Repeat(" ", 64*1024), 0},
	}
	for _, tc := range cases {
		server := newFeatureServer(t)
		server.set(tc.status, tc.body)
		server.setDelay(tc.delay)
		chat := featureChat(t, testFeatureOptions(server.endpoint()))
		importFeatureKeys(t, chat, v)
		keyedRequest(t, server, chat)
		if tc.delay > 0 {
			time.Sleep(600 * time.Millisecond)
		} else {
			time.Sleep(100 * time.Millisecond)
		}
		if chat.isEnabled("v1_send") {
			t.Errorf("%d %.40q (%d bytes): v1_send on", tc.status, tc.body, len(tc.body))
		}
		if got := sendVersion(t, chat, v).SignatureInfo.SignatureVersion; got != "7" {
			t.Errorf("%d %.40q (%d bytes): signature version %q, want 7", tc.status, tc.body, len(tc.body), got)
		}
	}
}

func TestAnUnreachableEndpointLeavesEveryFlagOff(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	endpoint := server.endpoint()
	server.Close()
	chat := featureChat(t, testFeatureOptions(endpoint))
	importFeatureKeys(t, chat, v)
	time.Sleep(300 * time.Millisecond)
	if chat.isEnabled("v1_send") {
		t.Fatal("v1_send on")
	}
	if !chat.featureRefetchDue() {
		t.Fatal("expected the key-bucketed fetch to stay due")
	}
	if got := sendVersion(t, chat, v).SignatureInfo.SignatureVersion; got != "7" {
		t.Errorf("signature version %q, want 7", got)
	}
}

func TestTheRecheckTurnsFlagsOffButNeverOn(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	opts := testFeatureOptions(server.endpoint())
	opts.refresh = 300 * time.Millisecond
	chat := featureChat(t, opts)
	importFeatureKeys(t, chat, v)
	waitFor(t, "v1_send on", func() bool { return chat.isEnabled("v1_send") })

	server.set(http.StatusOK, `{"features":{}}`)
	waitFor(t, "the re-check to turn v1_send off", func() bool { return !chat.isEnabled("v1_send") })
	if got := sendVersion(t, chat, v).SignatureInfo.SignatureVersion; got != "7" {
		t.Errorf("signature version %q, want 7", got)
	}

	server.set(http.StatusOK, `{"features":{"v1_send":true}}`)
	n := len(server.seen())
	waitFor(t, "two more re-checks", func() bool { return len(server.seen()) >= n+2 })
	if chat.isEnabled("v1_send") {
		t.Fatal("a re-check turned v1_send back on")
	}
}

func TestAFailedRecheckChangesNothing(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	opts := testFeatureOptions(server.endpoint())
	opts.refresh = 300 * time.Millisecond
	chat := featureChat(t, opts)
	importFeatureKeys(t, chat, v)
	waitFor(t, "v1_send on", func() bool { return chat.isEnabled("v1_send") })
	server.set(http.StatusServiceUnavailable, ``)
	n := len(server.seen())
	waitFor(t, "two failed re-checks", func() bool { return len(server.seen()) >= n+2 })
	if !chat.isEnabled("v1_send") {
		t.Fatal("a failed re-check changed the flags")
	}
}

func TestCloseStopsTheFetches(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	opts := testFeatureOptions(server.endpoint())
	opts.refresh = 300 * time.Millisecond
	opts.timeout = 10 * time.Second
	chat := newChat(opts)
	importFeatureKeys(t, chat, v)
	waitFor(t, "v1_send on", func() bool { return chat.isEnabled("v1_send") })
	server.setDelay(5 * time.Second)
	time.Sleep(400 * time.Millisecond)
	start := time.Now()
	chat.Close()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Close waited %v for the in-flight fetch", elapsed)
	}
	n := len(server.seen())
	time.Sleep(time.Second)
	if len(server.seen()) != n {
		t.Fatal("fetches continued after Close")
	}
}

func TestTheFetchesEndWithAnUnreferencedChat(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	opts := testFeatureOptions(server.endpoint())
	opts.refresh = 300 * time.Millisecond
	features := func() *featureSync {
		chat := newChat(opts)
		importFeatureKeys(t, chat, v)
		waitFor(t, "v1_send on", func() bool { return chat.isEnabled("v1_send") })
		return chat.features
	}()
	deadline := time.Now().Add(10 * time.Second)
	for stopped := false; !stopped; {
		runtime.GC()
		select {
		case <-features.done:
			stopped = true
		case <-time.After(50 * time.Millisecond):
			if time.Now().After(deadline) {
				t.Fatal("the fetches outlived the chat")
			}
		}
	}
	n := len(server.seen())
	time.Sleep(700 * time.Millisecond)
	if len(server.seen()) != n {
		t.Fatal("fetches continued after the chat was finalized")
	}
}

func TestAMalformedBodyIsRejectedAndChangesNothing(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	// The fetch never applies anything, so only the calls below change the
	// flags.
	server.set(http.StatusServiceUnavailable, ``)
	chat := featureChat(t, testFeatureOptions(server.endpoint()))
	importFeatureKeys(t, chat, v)
	keyedRequest(t, server, chat)
	bucket := chat.featureBucket()
	enableV1Send(t, chat)
	if err := chat.applyFeatureConfig(`[]`, bucket, true); err == nil {
		t.Fatal("expected an error")
	}
	if !chat.isEnabled("v1_send") {
		t.Fatal("a malformed body changed the flags")
	}
	if err := chat.applyFeatureConfig(`{"features":{}}`, bucket, true); err != nil {
		t.Fatal(err)
	}
	if chat.isEnabled("v1_send") {
		t.Fatal("the downgrade did not apply")
	}
}

func TestChatsAskingAtOnceShareARequest(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	server.setDelay(300 * time.Millisecond)
	chats := make([]*Chat, 4)
	for i := range chats {
		chats[i] = featureChat(t, testFeatureOptions(server.endpoint()))
	}
	all := func(cond func(*Chat) bool) func() bool {
		return func() bool {
			for _, chat := range chats {
				if !cond(chat) {
					return false
				}
			}
			return true
		}
	}
	waitFor(t, "the IP answer", all(func(c *Chat) bool { return c.isEnabled("v1_send") }))
	if got := server.seen(); !slices.Equal(got, []string{""}) {
		t.Fatalf("requests %q, want one without a bucket", got)
	}

	for _, chat := range chats {
		if err := chat.ImportKeys(ImportKeysParams{Keys: v.privateKeys(t)}); err != nil {
			t.Fatalf("ImportKeys failed: %v", err)
		}
	}
	waitFor(t, "the key answer", all(func(c *Chat) bool { return !c.featureRefetchDue() }))
	want := []string{"", strconv.Itoa(chats[0].featureBucket())}
	if got := server.seen(); !slices.Equal(got, want) {
		t.Fatalf("requests %q, want %q", got, want)
	}
}
