package chatxdk

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"time"
)

// Feature switches (GET /2/chat/features). The native core decides what to
// fetch and what an answer means; a new Chat performs its one GET here, in the
// background. Nothing here is API.

var featureClient = &http.Client{}

// featureFetch is a GET the core hands out.
type featureFetch struct {
	ID        uint64 `json:"id"`
	URL       string `json:"url"`
	TimeoutMs int64  `json:"timeout_ms"`
	MaxBytes  int64  `json:"max_bytes"`
}

// startFeatures starts c's one read of the feature switches: it performs the
// GET the core hands out, if any, in a goroutine of its own.
func (c *Chat) startFeatures() {
	defer runtime.KeepAlive(c)
	data, err := ffiFeatureStart(c.h)
	if err != nil || data == "" {
		return
	}
	var fetch featureFetch
	if json.Unmarshal([]byte(data), &fetch) != nil {
		return
	}
	go func() {
		status, body := featureGet(fetch)
		ffiFeatureComplete(fetch.ID, status, body)
	}()
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
