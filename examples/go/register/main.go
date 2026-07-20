// Command register performs one-time public-key registration for a bot identity.
//
// Registering a public key is a rare, rate-limited write (only a few per 24h
// per user) that establishes the identity every message is signed and encrypted
// against. This command does it safely and is re-runnable: if it is interrupted
// after generating keys but before the server confirms, running it again
// resumes the same identity instead of minting a new one.
//
// Flow:
//  1. Refuse if this identity is already registered (unless --force).
//  2. Generate the keypair once; persist the private-key blob AND the (public)
//     registration body to disk BEFORE any network call, so an error never
//     loses the identity and a retry re-sends the same registration.
//  3. Before POSTing, check whether this exact public key is already on the
//     account (a prior POST can apply server-side even after erroring) and adopt
//     it instead of re-registering — a duplicate POST wastes the daily budget.
//  4. POST the registration; stop cleanly on 429 rather than retrying.
//  5. Record the registered key version; optionally back the keys up with a PIN.
//
// Run: go run ./register --confirm
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xdevplatform/chat-xdk/go/chatxdk"
)

const stateDir = "state"

func blobPath() string   { return filepath.Join(stateDir, "private_keys.b64") }
func markerPath() string { return filepath.Join(stateDir, "registration.json") }

func main() {
	loadDotenv(".env")

	force := hasArg("--force")
	if !hasArg("--confirm") && !force {
		fmt.Println("This registers a bot identity (a rate-limited, one-time action).")
		fmt.Println("Re-run with --confirm when ready:  go run ./register --confirm")
		os.Exit(1)
	}
	if err := register(force); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func register(force bool) error {
	token := os.Getenv("X_ACCESS_TOKEN")
	if token == "" {
		return errors.New("set X_ACCESS_TOKEN (OAuth2 user token) in the environment or .env")
	}
	pin := os.Getenv("CHAT_PIN")

	marker := readMarker()
	if registered, _ := marker["registered"].(bool); registered && !force {
		return fmt.Errorf("already registered (version %v); pass --force only if you intend to create a NEW identity", marker["version"])
	}

	api := newXChatClient(token, os.Getenv("X_API_BASE_URL"))
	userID := os.Getenv("CHAT_BOT_USER_ID")
	if userID == "" {
		id, err := api.GetMyUserID()
		if err != nil {
			return err
		}
		userID = id
	}

	chat := chatxdk.New()
	defer chat.Close()

	// Resume an interrupted run with the SAME identity; only generate a fresh
	// one when there is no saved blob. Persisting the blob and the registration
	// body before the network POST is what makes a failed POST or Juicebox step
	// safe to retry without wasting the daily registration budget.
	var body map[string]any
	var version string
	savedBlob, blobErr := os.ReadFile(blobPath())
	_, hasBody := marker["body"]
	if blobErr == nil && hasBody && !force {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(savedBlob)))
		if err != nil {
			return fmt.Errorf("invalid saved blob: %w", err)
		}
		if err := chat.ImportKeys(raw); err != nil {
			return err
		}
		body, _ = marker["body"].(map[string]any)
		version = asString(marker["version"], "1")
		fmt.Printf("Resuming the saved identity (%s).\n", blobPath())
	} else {
		payload, err := chat.GenerateKeypairs()
		if err != nil {
			return err
		}
		version = "1"
		if payload.Version != nil {
			version = *payload.Version
		}
		// Only public material goes into the body, so it is safe to persist and
		// re-send on a later run.
		body = map[string]any{
			"public_key": map[string]any{
				"public_key":                    payload.PublicKey.PublicKey,
				"signing_public_key":            payload.PublicKey.SigningPublicKey,
				"identity_public_key_signature": payload.PublicKey.IdentityPublicKeySignature,
				"signing_public_key_signature":  payload.PublicKey.SigningPublicKeySignature,
				"registration_method":           payload.PublicKey.RegistrationMethod,
			},
			"version":          version,
			"generate_version": payload.GenerateVersion,
		}
		exported, err := chat.ExportKeys()
		if err != nil {
			return err
		}
		if err := saveBlob(base64.StdEncoding.EncodeToString(exported)); err != nil {
			return err
		}
		if err := writeMarker(map[string]any{"registered": false, "user_id": userID, "version": version, "body": body}); err != nil {
			return err
		}
		fmt.Printf("Generated a new identity; private keys saved to %s.\n", blobPath())
	}

	pkObj, ok := body["public_key"].(map[string]any)
	if !ok {
		return fmt.Errorf("saved registration body is malformed (%s); delete it to start over", markerPath())
	}
	ourPublicKey, _ := pkObj["public_key"].(string)

	// Reconcile: if our exact public key is already on the account, adopt it
	// rather than POSTing again (a prior POST may have applied after erroring).
	existing, err := api.GetPublicKeys(userID)
	if err != nil {
		return err
	}
	if v, found := findRegisteredVersion(existing, ourPublicKey); found {
		if v != "" {
			version = v
		}
		fmt.Printf("Public key already registered on the account (version %s); skipping POST.\n", version)
	} else {
		fmt.Printf("Registering public key version %s …\n", version)
		resp, err := api.AddUserPublicKey(userID, body)
		var limited *rateLimitedError
		if errors.As(err, &limited) {
			when := "the next window"
			if limited.hasReset {
				when = time.Unix(limited.resetEpoch, 0).UTC().Format(time.RFC3339)
			}
			return fmt.Errorf("registration is rate limited (429); the daily budget is exhausted — wait until %s and re-run (the saved identity resumes, so no budget is wasted)", when)
		}
		if err != nil {
			return err
		}
		if v := versionFromResponse(resp); v != "" {
			version = v
		}
	}

	if err := chat.SetIdentity(userID, version); err != nil {
		return err
	}
	if err := writeMarker(map[string]any{
		"registered":    true,
		"user_id":       userID,
		"version":       version,
		"registered_at": time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		return err
	}

	// Optional Juicebox backup. The private-key blob is already saved, so this
	// is best-effort: a failure here does not lose the identity.
	if pin != "" {
		cfg, _, cfgErr := api.GetJuiceboxConfig(userID)
		if cfgErr == nil {
			_, cfgErr = chat.Setup([]byte(pin), cfg)
		}
		if cfgErr != nil {
			fmt.Fprintf(os.Stderr, "Juicebox backup failed (keys are still saved locally): %v\n", cfgErr)
		} else {
			fmt.Println("Stored the keys in Juicebox under the PIN.")
		}
	}

	blob := strings.TrimSpace(string(mustReadFile(blobPath())))
	fmt.Println()
	fmt.Println("Registration complete.")
	fmt.Printf("  version:      %s\n", version)
	fmt.Printf("  private keys: %s (mode 600)\n", blobPath())
	fmt.Println("Add these to .env to run the bot:")
	fmt.Printf("  CHAT_PRIVATE_KEYS_B64=%s\n", blob)
	fmt.Printf("  CHAT_SIGNING_KEY_VERSION=%s\n", version)
	return nil
}

// -- Marker + blob persistence ----------------------------------------------

func readMarker() map[string]any {
	data, err := os.ReadFile(markerPath())
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	if json.Unmarshal(data, &m) != nil {
		return map[string]any{}
	}
	return m
}

func writeMarker(marker map[string]any) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(markerPath(), append(data, '\n'), 0o600)
}

// saveBlob writes the exported private keys to disk (mode 600).
func saveBlob(blob string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(blobPath(), []byte(blob+"\n"), 0o600)
}

func mustReadFile(path string) []byte {
	data, _ := os.ReadFile(path)
	return data
}

// -- Minimal X Chat API client for the register command ---------------------

type xChatClient struct {
	baseURL     string
	accessToken string
	http        *http.Client
}

func newXChatClient(accessToken, baseURL string) *xChatClient {
	if baseURL == "" {
		baseURL = "https://api.x.com"
	}
	return &xChatClient{baseURL: baseURL, accessToken: accessToken, http: &http.Client{Timeout: 30 * time.Second}}
}

// rateLimitedError signals the public-key write bucket is exhausted (HTTP 429).
// The endpoint allows only a few writes per 24h; resetEpoch is when the window
// frees up. Retrying before then just fails again.
type rateLimitedError struct {
	resetEpoch int64
	hasReset   bool
}

func (e *rateLimitedError) Error() string { return "public-key registration rate limited (HTTP 429)" }

func (c *xChatClient) GetMyUserID() (string, error) {
	var out struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := c.get("/2/users/me", &out); err != nil {
		return "", err
	}
	return out.Data.ID, nil
}

// GetPublicKeys fetches a user's registered public keys (to check your own
// before registering).
func (c *xChatClient) GetPublicKeys(userID string) ([]map[string]any, error) {
	var out struct {
		Data json.RawMessage `json:"data"`
	}
	path := fmt.Sprintf("/2/users/%s/public_keys", url.PathEscape(userID))
	if err := c.get(path, &out); err != nil {
		return nil, err
	}
	return decodeItems(out.Data), nil
}

// GetJuiceboxConfig builds the Juicebox config JSON + latest key version for
// the optional PIN backup. Every public_key field (juicebox_config included)
// is always returned; the route takes no public_key.fields parameter.
func (c *xChatClient) GetJuiceboxConfig(userID string) (string, string, error) {
	var out struct {
		Data json.RawMessage `json:"data"`
	}
	path := fmt.Sprintf("/2/users/%s/public_keys", url.PathEscape(userID))
	if err := c.get(path, &out); err != nil {
		return "", "", err
	}
	items := decodeItems(out.Data)
	if len(items) == 0 {
		return "", "", errors.New("no public keys returned")
	}
	latest := items[0]
	for _, it := range items[1:] {
		if versionInt(it["public_key_version"]) >= versionInt(latest["public_key_version"]) {
			latest = it
		}
	}
	cfg, ok := latest["juicebox_config"]
	if !ok || cfg == nil {
		return "", "", errors.New("no juicebox_config on the account")
	}
	// The X API juicebox_config object is accepted as-is: the core reads
	// key_store_token_map_json verbatim and auth tokens from token_map.
	raw, err := json.Marshal(cfg)
	if err != nil {
		return "", "", err
	}
	return string(raw), asString(latest["public_key_version"], "1"), nil
}

// AddUserPublicKey registers a public key: POST /2/users/{id}/public_keys.
// body is the registration object in snake_case wire form. Returns a
// *rateLimitedError on 429 so the caller can stop instead of burning the budget.
func (c *xChatClient) AddUserPublicKey(userID string, body map[string]any) (map[string]any, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL+fmt.Sprintf("/2/users/%s/public_keys", url.PathEscape(userID)), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusTooManyRequests {
		limited := &rateLimitedError{}
		if reset := resp.Header.Get("x-user-limit-24hour-reset"); reset != "" {
			if n, perr := strconv.ParseInt(reset, 10, 64); perr == nil {
				limited.resetEpoch, limited.hasReset = n, true
			}
		}
		return nil, limited
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("x api POST public_keys: %d %s", resp.StatusCode, string(data))
	}
	out := map[string]any{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (c *xChatClient) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("x api GET %s: %d %s", path, resp.StatusCode, string(data))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// -- Small helpers ----------------------------------------------------------

// decodeItems parses a public_keys `data` field that may be an object or array.
func decodeItems(raw json.RawMessage) []map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var arr []map[string]any
	if json.Unmarshal(raw, &arr) == nil {
		return arr
	}
	var one map[string]any
	if json.Unmarshal(raw, &one) == nil {
		return []map[string]any{one}
	}
	return nil
}

// findRegisteredVersion returns the version of the entry whose identity public
// key matches ours, if any.
func findRegisteredVersion(items []map[string]any, ourPublicKey string) (string, bool) {
	for _, it := range items {
		pk, _ := it["public_key"].(string)
		if pk == ourPublicKey && ourPublicKey != "" {
			return asString(it["public_key_version"], ""), true
		}
	}
	return "", false
}

func versionFromResponse(resp map[string]any) string {
	data := resp["data"]
	if arr, ok := data.([]any); ok {
		if len(arr) == 0 {
			return ""
		}
		data = arr[0]
	}
	m, ok := data.(map[string]any)
	if !ok {
		return ""
	}
	return asString(m["public_key_version"], "")
}

func asString(v any, fallback string) string {
	switch s := v.(type) {
	case string:
		if s != "" {
			return s
		}
	case float64:
		return strconv.FormatInt(int64(s), 10)
	}
	return fallback
}

func versionInt(v any) int64 {
	switch s := v.(type) {
	case string:
		n, _ := strconv.ParseInt(s, 10, 64)
		return n
	case float64:
		return int64(s)
	}
	return 0
}

func hasArg(name string) bool {
	for _, a := range os.Args[1:] {
		if a == name {
			return true
		}
	}
	return false
}

// loadDotenv is a tiny .env loader so the example has no extra dependencies.
func loadDotenv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		if _, ok := os.LookupEnv(strings.TrimSpace(k)); !ok {
			os.Setenv(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
}
