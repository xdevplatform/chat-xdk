package chatxdk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

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

func (s *featureServer) params(refreshSeconds int) LoadFeatureConfigParams {
	return LoadFeatureConfigParams{Endpoint: s.URL + "/2/chat/features", TimeoutMs: 1000, RefreshSeconds: refreshSeconds}
}

func enableV1Send(t *testing.T, chat *Chat) {
	t.Helper()
	if err := chat.ApplyFeatureConfig(`{"features":{"v1_send":true}}`, chat.FeatureBucket(), false); err != nil {
		t.Fatalf("ApplyFeatureConfig failed: %v", err)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("timed out waiting for %s", what)
	}
}

func featureChat(t *testing.T, v sdkVectors, withKeys bool) *Chat {
	t.Helper()
	chat := New()
	t.Cleanup(chat.Close)
	if withKeys {
		importFeatureKeys(t, chat, v)
	}
	return chat
}

func importFeatureKeys(t *testing.T, chat *Chat, v sdkVectors) {
	t.Helper()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}
	if err := chat.SetIdentity(v.EventSenderID, v.EventSigningKeyVersion); err != nil {
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

func TestEveryFlagIsOffAndSendsAreV0BeforeAnyLoad(t *testing.T) {
	v := loadVectors(t)
	chat := featureChat(t, v, true)
	if chat.IsEnabled(FeatureV1Send) {
		t.Fatal("v1_send on before any load")
	}
	payload := sendVersion(t, chat, v)
	if payload.SignatureInfo.SignatureVersion != "7" {
		t.Errorf("signature version %q, want 7", payload.SignatureInfo.SignatureVersion)
	}
	if payload.XdkVersion == "" {
		t.Error("expected xdk_version")
	}
}

func TestLoadAfterKeysSendsTheKeyBucketAndSwitchesToV1(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	chat := featureChat(t, v, true)
	bucket := chat.FeatureBucket()
	if bucket < 0 || bucket >= 10000 {
		t.Fatalf("bucket %d out of range", bucket)
	}
	if !chat.LoadFeatureConfig(context.Background(), server.params(-1)) {
		t.Fatal("LoadFeatureConfig did not apply")
	}
	if got := server.seen(); len(got) != 1 || got[0] != strconv.Itoa(bucket) {
		t.Fatalf("buckets %v, want [%d]", got, bucket)
	}
	if !chat.IsEnabled(FeatureV1Send) {
		t.Fatal("v1_send off after load")
	}
	if got := sendVersion(t, chat, v).SignatureInfo.SignatureVersion; got != "10" {
		t.Errorf("signature version %q, want 10", got)
	}
}

func TestUnknownKeysAreReadableAndMissingKeysAreOff(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	server.set(http.StatusOK, `{"features":{"later_flag":true,"v1_send":"yes"},"extra":1}`)
	chat := featureChat(t, v, true)
	if !chat.LoadFeatureConfig(context.Background(), server.params(-1)) {
		t.Fatal("LoadFeatureConfig did not apply")
	}
	if !chat.IsEnabled("later_flag") || chat.IsEnabled(FeatureV1Send) || chat.IsEnabled("missing") {
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
	}
	for _, tc := range cases {
		server := newFeatureServer(t)
		server.set(tc.status, tc.body)
		server.setDelay(tc.delay)
		chat := featureChat(t, v, true)
		params := server.params(-1)
		params.TimeoutMs = 300
		if chat.LoadFeatureConfig(context.Background(), params) {
			t.Errorf("%d %q: applied", tc.status, tc.body)
		}
		if chat.IsEnabled(FeatureV1Send) {
			t.Errorf("%d %q: v1_send on", tc.status, tc.body)
		}
		if got := sendVersion(t, chat, v).SignatureInfo.SignatureVersion; got != "7" {
			t.Errorf("%d %q: signature version %q, want 7", tc.status, tc.body, got)
		}
	}
}

func TestLoadBeforeKeysRefetchesOnceWithTheKeyBucket(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	chat := featureChat(t, v, false)
	if chat.FeatureBucket() != -1 {
		t.Fatal("bucket before keys")
	}
	if !chat.LoadFeatureConfig(context.Background(), server.params(-1)) {
		t.Fatal("LoadFeatureConfig did not apply")
	}
	if got := server.seen(); len(got) != 1 || got[0] != "" {
		t.Fatalf("buckets %v, want one bucketless request", got)
	}
	if !chat.IsEnabled(FeatureV1Send) {
		t.Fatal("the IP-bucketed answer should apply while no keys are loaded")
	}

	server.set(http.StatusOK, `{"features":{"v1_send":false}}`)
	importFeatureKeys(t, chat, v)
	if chat.IsEnabled(FeatureV1Send) {
		t.Fatal("flags must read off until the key-bucketed refetch")
	}
	want := strconv.Itoa(chat.FeatureBucket())
	waitFor(t, "the key-bucketed refetch", func() bool {
		for _, b := range server.seen() {
			if b == want {
				return !chat.FeatureRefetchDue()
			}
		}
		return false
	})
	if chat.IsEnabled(FeatureV1Send) {
		t.Fatal("the refetch answered false")
	}

	other := featureChat(t, v, false)
	server.set(http.StatusOK, `{"features":{"v1_send":false}}`)
	if !other.LoadFeatureConfig(context.Background(), server.params(-1)) {
		t.Fatal("LoadFeatureConfig did not apply")
	}
	server.set(http.StatusOK, `{"features":{"v1_send":true}}`)
	importFeatureKeys(t, other, v)
	waitFor(t, "the refetch to turn v1_send on", func() bool { return other.IsEnabled(FeatureV1Send) })
}

func TestTheRecheckTurnsFlagsOffButNeverOn(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	chat := featureChat(t, v, true)
	if !chat.LoadFeatureConfig(context.Background(), server.params(1)) {
		t.Fatal("LoadFeatureConfig did not apply")
	}
	server.set(http.StatusOK, `{"features":{}}`)
	waitFor(t, "the re-check to turn v1_send off", func() bool { return !chat.IsEnabled(FeatureV1Send) })

	server.set(http.StatusOK, `{"features":{"v1_send":true}}`)
	n := len(server.seen())
	waitFor(t, "two more re-checks", func() bool { return len(server.seen()) >= n+2 })
	if chat.IsEnabled(FeatureV1Send) {
		t.Fatal("a re-check turned v1_send back on")
	}
}

func TestAFailedRecheckChangesNothing(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	chat := featureChat(t, v, true)
	if !chat.LoadFeatureConfig(context.Background(), server.params(1)) {
		t.Fatal("LoadFeatureConfig did not apply")
	}
	server.set(http.StatusServiceUnavailable, ``)
	n := len(server.seen())
	waitFor(t, "two failed re-checks", func() bool { return len(server.seen()) >= n+2 })
	if !chat.IsEnabled(FeatureV1Send) {
		t.Fatal("a failed re-check changed the flags")
	}
}

func TestCloseStopsTheRefresher(t *testing.T) {
	v := loadVectors(t)
	server := newFeatureServer(t)
	chat := New()
	importFeatureKeys(t, chat, v)
	if !chat.LoadFeatureConfig(context.Background(), server.params(1)) {
		t.Fatal("LoadFeatureConfig did not apply")
	}
	server.setDelay(5 * time.Second)
	time.Sleep(1200 * time.Millisecond)
	start := time.Now()
	chat.Close()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Close waited %v for the refresher", elapsed)
	}
	n := len(server.seen())
	time.Sleep(2500 * time.Millisecond)
	if len(server.seen()) != n {
		t.Fatal("the refresher kept running after Close")
	}
	if chat.LoadFeatureConfig(context.Background(), server.params(1)) {
		t.Fatal("LoadFeatureConfig applied on a closed chat")
	}
}

func TestApplyFeatureConfigRejectsAMalformedBody(t *testing.T) {
	v := loadVectors(t)
	chat := featureChat(t, v, true)
	enableV1Send(t, chat)
	if err := chat.ApplyFeatureConfig(`[]`, chat.FeatureBucket(), true); err == nil {
		t.Fatal("expected an error")
	}
	if !chat.IsEnabled(FeatureV1Send) {
		t.Fatal("a malformed body changed the flags")
	}
	if err := chat.ApplyFeatureConfig(`{"features":{}}`, chat.FeatureBucket(), true); err != nil {
		t.Fatal(err)
	}
	if chat.IsEnabled(FeatureV1Send) {
		t.Fatal("the downgrade did not apply")
	}
}
