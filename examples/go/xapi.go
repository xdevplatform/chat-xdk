package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// apiConvID converts a conversation id to the form the X API URL paths expect
// (hyphen-separated), regardless of the colon-separated form found in events.
func apiConvID(id string) string {
	return strings.ReplaceAll(id, ":", "-")
}

// XChatClient is a minimal X Chat API client over HTTP. Authentication is an
// OAuth2 user access token (scopes dm.read + dm.write).
type XChatClient struct {
	baseURL     string
	accessToken string
	http        *http.Client
}

func NewXChatClient(accessToken, baseURL string) *XChatClient {
	if baseURL == "" {
		baseURL = "https://api.x.com"
	}
	return &XChatClient{
		baseURL:     baseURL,
		accessToken: accessToken,
		http:        &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *XChatClient) do(method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("x api %s %s: %d %s", method, path, resp.StatusCode, string(data))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// EventItem is one element of the conversation events response. ID is the
// event's sequence id (the API exposes sequence_id as id).
type EventItem struct {
	ID             string `json:"id"`
	ConversationID string `json:"conversation_id"`
	SenderID       string `json:"sender_id"`
	EncodedEvent   string `json:"encoded_event"`
	IsTrusted      bool   `json:"is_trusted"`
}

type eventsResponse struct {
	Data []EventItem    `json:"data"`
	Meta map[string]any `json:"meta"`
}

type publicKeysResponse struct {
	Data []map[string]any `json:"data"`
}

type meResponse struct {
	Data struct {
		ID string `json:"id"`
	} `json:"data"`
}

// GetMyUserID returns the authenticated user's ID.
func (c *XChatClient) GetMyUserID() (string, error) {
	var out meResponse
	if err := c.do(http.MethodGet, "/2/users/me", nil, &out); err != nil {
		return "", err
	}
	return out.Data.ID, nil
}

// GetPublicKeys fetches another user's registered public keys. Every field
// of the public_key resource (public_key, signing_public_key,
// identity_public_key_signature, public_key_version, juicebox_config) is
// always included; the route takes no public_key.fields parameter.
func (c *XChatClient) GetPublicKeys(userID string) ([]map[string]any, error) {
	var out publicKeysResponse
	path := fmt.Sprintf("/2/users/%s/public_keys", url.PathEscape(userID))
	if err := c.do(http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// GetEvents fetches the raw (encrypted) events for a conversation.
func (c *XChatClient) GetEvents(conversationID string, maxResults int, paginationToken string) ([]EventItem, string, error) {
	q := url.Values{}
	q.Set("max_results", fmt.Sprintf("%d", maxResults))
	if paginationToken != "" {
		q.Set("pagination_token", paginationToken)
	}
	path := fmt.Sprintf("/2/chat/conversations/%s/events?%s", url.PathEscape(apiConvID(conversationID)), q.Encode())
	var out eventsResponse
	if err := c.do(http.MethodGet, path, nil, &out); err != nil {
		return nil, "", err
	}
	next, _ := out.Meta["next_token"].(string)
	return out.Data, next, nil
}

// -- Conversation / key management -------------------------------------------

// AddConversationKeys posts a prepared conversation-key change (initialize or
// rotate). body is the request shape built by PrepToRequest. For a 1:1,
// conversationID may be the recipient's user ID; the server derives (and
// returns) the canonical conversation ID.
func (c *XChatClient) AddConversationKeys(conversationID string, body map[string]any) (map[string]any, error) {
	path := fmt.Sprintf("/2/chat/conversations/%s/keys", url.PathEscape(apiConvID(conversationID)))
	var out map[string]any
	if err := c.do(http.MethodPost, path, body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// InitializeGroup mints a new group conversation id (`g…`).
func (c *XChatClient) InitializeGroup() (string, error) {
	var out struct {
		Data struct {
			ConversationID string `json:"conversation_id"`
		} `json:"data"`
	}
	if err := c.do(http.MethodPost, "/2/chat/conversations/group/initialize", map[string]any{}, &out); err != nil {
		return "", err
	}
	return out.Data.ConversationID, nil
}

// CreateConversation creates a group conversation. body carries
// conversation_id, group_members, group_admins, and the two-signature key
// change from ChatCore.PrepareGroupCreate.
func (c *XChatClient) CreateConversation(body map[string]any) (map[string]any, error) {
	var out map[string]any
	if err := c.do(http.MethodPost, "/2/chat/conversations/group", body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// AddGroupMembers adds members to a group. body carries user_ids plus the
// rotated key change from ChatCore.PrepareGroupMembersChange.
func (c *XChatClient) AddGroupMembers(conversationID string, body map[string]any) (map[string]any, error) {
	path := fmt.Sprintf("/2/chat/conversations/%s/members", url.PathEscape(conversationID))
	var out map[string]any
	if err := c.do(http.MethodPost, path, body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// -- Media (encrypted blobs) ----------------------------------------------------

// uploadChunk is the append segment size for the three-step media upload.
const uploadChunk = 3 * 1024 * 1024

// UploadMedia uploads an encrypted media blob; returns its media_hash_key.
//
// Three-step flow: initialize (returns an upload session and the hash key),
// append (3 MB segments), finalize. The media endpoints take the colon form
// of the conversation id in the body.
func (c *XChatClient) UploadMedia(conversationID string, ciphertext []byte) (string, error) {
	conv := strings.ReplaceAll(conversationID, "-", ":")
	var init struct {
		Data struct {
			SessionID    string `json:"session_id"`
			MediaHashKey string `json:"media_hash_key"`
		} `json:"data"`
	}
	err := c.do(http.MethodPost, "/2/chat/media/upload/initialize", map[string]any{
		"conversation_id": conv,
		"total_bytes":     len(ciphertext),
	}, &init)
	if err != nil {
		return "", err
	}
	sessionID, mediaHashKey := init.Data.SessionID, init.Data.MediaHashKey
	if sessionID == "" || mediaHashKey == "" {
		return "", fmt.Errorf("media upload initialize failed: session_id=%q media_hash_key=%q", sessionID, mediaHashKey)
	}

	segment := 0
	for offset := 0; offset < len(ciphertext); offset += uploadChunk {
		end := min(offset+uploadChunk, len(ciphertext))
		appendPath := fmt.Sprintf("/2/chat/media/upload/%s/append", url.PathEscape(sessionID))
		err := c.do(http.MethodPost, appendPath, map[string]any{
			"conversation_id": conv,
			"media_hash_key":  mediaHashKey,
			"segment_index":   fmt.Sprintf("%d", segment),
			"media":           base64.StdEncoding.EncodeToString(ciphertext[offset:end]),
		}, nil)
		if err != nil {
			return "", err
		}
		segment++
	}

	finalizePath := fmt.Sprintf("/2/chat/media/upload/%s/finalize", url.PathEscape(sessionID))
	err = c.do(http.MethodPost, finalizePath, map[string]any{
		"conversation_id": conv,
		"media_hash_key":  mediaHashKey,
		"num_parts":       fmt.Sprintf("%d", segment),
	}, nil)
	if err != nil {
		return "", err
	}
	return mediaHashKey, nil
}

// DownloadMedia downloads an encrypted media blob as raw bytes.
//
// The response body is binary ciphertext — it is returned untouched as bytes;
// any text decoding would corrupt it. The download path takes the hyphen form
// of the conversation id.
func (c *XChatClient) DownloadMedia(conversationID, mediaHashKey string) ([]byte, error) {
	path := fmt.Sprintf("/2/chat/media/%s/%s", url.PathEscape(apiConvID(conversationID)), url.PathEscape(mediaHashKey))
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("x api GET %s: %d %s", path, resp.StatusCode, string(data))
	}
	return data, nil
}

// -- Sending -------------------------------------------------------------------

// SendMessage posts an encrypted message produced by ChatCore.EncryptReply.
func (c *XChatClient) SendMessage(conversationID string, body *SendBody) error {
	path := fmt.Sprintf("/2/chat/conversations/%s/messages", url.PathEscape(apiConvID(conversationID)))
	return c.do(http.MethodPost, path, body, nil)
}
