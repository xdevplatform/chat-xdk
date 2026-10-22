package chatxdk

import (
	"context"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Feature switches (GET /2/chat/features). Internal: every Chat fetches them
// itself, without blocking or failing, and sends stay v0 unless a response
// turns v1_send on. Nothing here is API. CHAT_XDK_FEATURES_ENDPOINT, which
// only this repository's tests set, overrides the endpoint.

const (
	featuresEndpoint         = "https://api.x.com/2/chat/features"
	featuresEndpointEnv      = "CHAT_XDK_FEATURES_ENDPOINT"
	maxFeaturesBody          = 64 * 1024
	maxFeatureRefetchBackoff = 60 * time.Second
)

// featureOptions configures the goroutine that fetches a chat's feature
// switches. New uses defaultFeatureOptions; tests pass shorter timings.
type featureOptions struct {
	endpoint string
	timeout  time.Duration
	refresh  time.Duration
	keyPoll  time.Duration
}

func defaultFeatureOptions() featureOptions {
	endpoint := os.Getenv(featuresEndpointEnv)
	if endpoint == "" {
		endpoint = featuresEndpoint
	}
	return featureOptions{
		endpoint: endpoint,
		timeout:  2 * time.Second,
		refresh:  300 * time.Second,
		keyPoll:  time.Second,
	}
}

// featureSync is the part of a Chat its feature goroutine uses. The
// goroutine holds only this, never the Chat, so an unreferenced Chat is
// still finalized, which stops the goroutine.
type featureSync struct {
	// mu orders the goroutine's native calls (read) against the calls that
	// take the handle exclusively and Close (write).
	mu       sync.RWMutex
	h        handle // nil once the chat is closed
	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
}

func startFeatureSwitches(h handle, opts featureOptions) *featureSync {
	f := &featureSync{h: h, stop: make(chan struct{}), done: make(chan struct{})}
	go f.run(opts)
	return f
}

// close stops the goroutine, waits for it, and drops the handle.
func (f *featureSync) close() {
	f.stopOnce.Do(func() { close(f.stop) })
	<-f.done
	f.mu.Lock()
	f.h = nil
	f.mu.Unlock()
}

// run fetches the flags now (retrying once), again with the key's bucket
// once keys load (retrying with backoff), and re-checks them every refresh
// interval with a fetch that can only turn flags off, until stop closes.
func (f *featureSync) run(opts featureOptions) {
	defer close(f.done)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-f.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	client := &http.Client{Timeout: opts.timeout}

	if !f.fetch(ctx, client, opts.endpoint, false) {
		f.fetch(ctx, client, opts.endpoint, false)
	}
	nextRecheck := time.Now().Add(opts.refresh)
	var retryAt time.Time
	backoff := time.Second
	for {
		now := time.Now()
		if f.refetchDue() {
			if !now.Before(retryAt) {
				if f.fetch(ctx, client, opts.endpoint, false) {
					backoff = time.Second
					nextRecheck = time.Now().Add(opts.refresh)
				} else {
					retryAt = time.Now().Add(backoff)
					backoff = min(backoff*2, maxFeatureRefetchBackoff)
				}
			}
		} else if opts.refresh > 0 && !now.Before(nextRecheck) {
			f.fetch(ctx, client, opts.endpoint, true)
			nextRecheck = time.Now().Add(opts.refresh)
		}

		keyed := f.keyed()
		if keyed && opts.refresh <= 0 {
			return
		}
		// Until a response for the key's bucket applies, watch for keys to
		// load; afterwards, wake only for the re-check.
		wait := opts.keyPoll
		if keyed {
			wait = max(time.Until(nextRecheck), 0)
		}
		timer := time.NewTimer(wait)
		select {
		case <-f.stop:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// fetch fetches the flags for the current bucket and applies them,
// reporting whether a response was applied.
func (f *featureSync) fetch(ctx context.Context, client *http.Client, endpoint string, downgradeOnly bool) bool {
	f.mu.RLock()
	if f.h == nil {
		f.mu.RUnlock()
		return false
	}
	bucket := ffiFeatureBucket(f.h)
	f.mu.RUnlock()

	body, ok := getFeatures(ctx, client, featuresURL(endpoint, bucket))
	if !ok {
		return false
	}

	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.h != nil && ffiApplyFeatureConfig(f.h, body, bucket, downgradeOnly) == nil
}

func (f *featureSync) refetchDue() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.h != nil && ffiFeatureRefetchDue(f.h) == 1
}

// keyed reports whether a response for the loaded key's bucket applied.
func (f *featureSync) keyed() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.h != nil && ffiFeatureBucket(f.h) >= 0 && ffiFeatureRefetchDue(f.h) == 0
}

func featuresURL(endpoint string, bucket int) string {
	if bucket < 0 {
		return endpoint
	}
	sep := "?"
	if strings.Contains(endpoint, "?") {
		sep = "&"
	}
	return endpoint + sep + "bucket=" + strconv.Itoa(bucket)
}

func getFeatures(ctx context.Context, client *http.Client, url string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeaturesBody+1))
	if err != nil || len(body) > maxFeaturesBody {
		return "", false
	}
	return string(body), true
}
