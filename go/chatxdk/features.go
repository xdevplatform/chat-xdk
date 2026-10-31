package chatxdk

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"time"
)

// Feature switches (GET /2/chat/features). A Chat reads them when it is
// created and when SetIdentity gives it a new URL, and again after each
// answer: the native core decides what to fetch, when to fetch it again and
// what an answer means, and this file performs each GET it hands out, in the
// background. Nothing here is API.

// featureClient keeps the read anonymous: with no Jar it stores and sends no
// cookies, and it follows no redirect, so a 3xx answer reaches the core as a
// failed read rather than as a request to another URL.
var featureClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// featureFetch is a GET the core hands out, to start DelayMs from now.
type featureFetch struct {
	ID        uint64 `json:"id"`
	URL       string `json:"url"`
	TimeoutMs int64  `json:"timeout_ms"`
	MaxBytes  int64  `json:"max_bytes"`
	DelayMs   int64  `json:"delay_ms"`
}

// startFeatures starts c's reads of the feature switches for its identity:
// it performs the GET the core hands out, if any, and then each GET the core
// hands back, in a goroutine of its own.
func (c *Chat) startFeatures() {
	defer runtime.KeepAlive(c)
	data, err := ffiFeatureStart(c.h)
	if err != nil || data == "" {
		return
	}
	go performFeatureFetches(data)
}

// performFeatureFetches performs the GET data describes, after its delay, and
// the refresh or retry each result returns, until none does.
func performFeatureFetches(data string) {
	for data != "" {
		var fetch featureFetch
		if json.Unmarshal([]byte(data), &fetch) != nil {
			return
		}
		time.Sleep(time.Duration(fetch.DelayMs) * time.Millisecond)
		status, body := featureGet(fetch)
		next, err := ffiFeatureComplete(fetch.ID, status, body)
		if err != nil {
			return
		}
		data = next
	}
}

// featureGet performs the GET within its timeout, reading the body to its end
// or to one byte past MaxBytes. Status 0 when no complete response arrived.
func featureGet(fetch featureFetch) (int, []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(fetch.TimeoutMs)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetch.URL, nil)
	if err != nil {
		return 0, nil
	}
	req.Header.Set("Accept", "application/json")
	resp, err := featureClient.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, fetch.MaxBytes+1))
	if err != nil {
		return 0, nil
	}
	return resp.StatusCode, body
}
