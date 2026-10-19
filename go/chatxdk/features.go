package chatxdk

import (
	"context"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// FeaturesEndpoint is the default URL of the feature-switch endpoint,
// GET /2/chat/features.
const FeaturesEndpoint = "https://api.x.com/2/chat/features"

// FeatureV1Send is the feature switch that turns on v1 sends (per-message
// keys). While it is off, sends use the v0 format (0.5.x).
const FeatureV1Send = "v1_send"

const (
	defaultFeatureTimeout    = 2 * time.Second
	defaultFeatureRefresh    = 300 * time.Second
	maxFeaturesBody          = 64 * 1024
	maxFeatureRefetchBackoff = 60 * time.Second
)

// LoadFeatureConfigParams configures LoadFeatureConfig.
type LoadFeatureConfigParams struct {
	// Endpoint is the URL of GET /2/chat/features; empty selects
	// FeaturesEndpoint.
	Endpoint string
	// TimeoutMs bounds each request; 0 selects 2000.
	TimeoutMs int
	// RefreshSeconds is the interval of the background re-check, which can
	// only turn flags off; 0 selects 300 and a negative value disables it.
	RefreshSeconds int
}

type featureRefresher struct {
	stop chan struct{}
	done chan struct{}
}

// LoadFeatureConfig fetches the feature switches from GET /2/chat/features
// and applies them, returning true when a server response was applied.
//
// Call it at startup after loading keys and SetIdentity, so the request
// carries FeatureBucket. If keys load later, the flags are fetched once
// more with the key's bucket, and every flag reads off until they are. A
// background goroutine re-checks every RefreshSeconds; a re-check can only
// turn flags off. The goroutine runs until Close or the next
// LoadFeatureConfig; ctx bounds only the first fetch.
//
// Any failure (network error, timeout, a status other than 200, or a
// malformed body) leaves the flags unchanged, so after a failed first load
// every flag is off and sends stay v0.
func (c *Chat) LoadFeatureConfig(ctx context.Context, params LoadFeatureConfigParams) bool {
	defer runtime.KeepAlive(c)
	c.stopFeatureRefresh()
	if c.h == nil {
		return false
	}

	endpoint := params.Endpoint
	if endpoint == "" {
		endpoint = FeaturesEndpoint
	}
	timeout := defaultFeatureTimeout
	if params.TimeoutMs > 0 {
		timeout = time.Duration(params.TimeoutMs) * time.Millisecond
	}
	refresh := defaultFeatureRefresh
	if params.RefreshSeconds > 0 {
		refresh = time.Duration(params.RefreshSeconds) * time.Second
	} else if params.RefreshSeconds < 0 {
		refresh = 0
	}
	client := &http.Client{Timeout: timeout}

	applied := c.fetchFeatures(ctx, client, endpoint, false) ||
		c.fetchFeatures(ctx, client, endpoint, false)

	r := &featureRefresher{stop: make(chan struct{}), done: make(chan struct{})}
	c.refresher = r
	go c.refreshFeatures(r, client, endpoint, refresh)
	return applied
}

// IsEnabled reports whether the feature switch name is on. It is off for
// names the last response did not turn on, before any response applies, and
// while FeatureRefetchDue holds.
func (c *Chat) IsEnabled(name string) bool {
	defer runtime.KeepAlive(c)
	return ffiIsEnabled(c.h, name) == 1
}

// FeatureBucket returns the bucket (0-9999) GET /2/chat/features evaluates
// this instance's flags for, derived from the loaded identity public key,
// or -1 until keys load. Send it as the request's bucket query parameter.
func (c *Chat) FeatureBucket() int {
	defer runtime.KeepAlive(c)
	return ffiFeatureBucket(c.h)
}

// ApplyFeatureConfig applies a GET /2/chat/features response body.
// LoadFeatureConfig fetches and applies for you; call this only when
// fetching through your own HTTP stack. bucket is the bucket the request
// carried (FeatureBucket), or -1 when it carried none. downgradeOnly only
// turns flags off (a periodic re-check) instead of replacing them. A body
// that is not a JSON object with a "features" object is an error and changes
// nothing.
func (c *Chat) ApplyFeatureConfig(json string, bucket int, downgradeOnly bool) error {
	defer runtime.KeepAlive(c)
	return ffiApplyFeatureConfig(c.h, json, bucket, downgradeOnly)
}

// FeatureRefetchDue reports whether keys loaded after a response to a
// request without a bucket applied, so the flags must be fetched again with
// FeatureBucket. Every flag reads off until they are.
func (c *Chat) FeatureRefetchDue() bool {
	defer runtime.KeepAlive(c)
	return ffiFeatureRefetchDue(c.h) == 1
}

func (c *Chat) stopFeatureRefresh() {
	if r := c.refresher; r != nil {
		close(r.stop)
		<-r.done
		c.refresher = nil
	}
}

// fetchFeatures fetches the flags for the current bucket and applies them,
// reporting whether a response was applied.
func (c *Chat) fetchFeatures(ctx context.Context, client *http.Client, endpoint string, downgradeOnly bool) bool {
	c.mu.RLock()
	if c.h == nil {
		c.mu.RUnlock()
		return false
	}
	bucket := ffiFeatureBucket(c.h)
	c.mu.RUnlock()

	body, ok := getFeatures(ctx, client, featuresURL(endpoint, bucket))
	if !ok {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.h == nil || ffiApplyFeatureConfig(c.h, body, bucket, downgradeOnly) != nil {
		return false
	}
	if !downgradeOnly {
		c.featureBucketless.Store(bucket < 0)
	}
	return true
}

func (c *Chat) featureRefetchDue() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.h != nil && ffiFeatureRefetchDue(c.h) == 1
}

// refreshFeatures re-fetches once keys load after a bucketless response and
// re-checks every refresh interval, until r.stop closes.
func (c *Chat) refreshFeatures(r *featureRefresher, client *http.Client, endpoint string, refresh time.Duration) {
	defer close(r.done)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-r.stop:
			cancel()
		case <-ctx.Done():
		}
	}()

	nextRecheck := time.Now().Add(refresh)
	var retryAt time.Time
	backoff := time.Second
	for {
		now := time.Now()
		if c.featureRefetchDue() {
			if !now.Before(retryAt) {
				if c.fetchFeatures(ctx, client, endpoint, false) {
					backoff = time.Second
					nextRecheck = now.Add(refresh)
				} else {
					retryAt = now.Add(backoff)
					backoff = min(backoff*2, maxFeatureRefetchBackoff)
				}
			}
		} else if refresh > 0 && !now.Before(nextRecheck) {
			c.fetchFeatures(ctx, client, endpoint, true)
			nextRecheck = now.Add(refresh)
		}

		watchingKeys := c.featureBucketless.Load()
		if !watchingKeys && refresh <= 0 {
			return
		}
		wait := time.Second
		if !watchingKeys {
			wait = max(time.Until(nextRecheck), 0)
		}
		timer := time.NewTimer(wait)
		select {
		case <-r.stop:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
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
