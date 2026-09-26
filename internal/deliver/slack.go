package deliver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Poster sends one message and returns its timestamp, the ID Slack gives it.
type Poster interface {
	Post(ctx context.Context, m Message) (string, error)
}

// SlackClient calls chat.postMessage with a bot token. It is a narrow client
// for the one method delivery needs, like the Vora client: no SDK, the standard
// library only.
type SlackClient struct {
	// BaseURL defaults to https://slack.com/api.
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// RateLimited is Slack refusing a call for now. After is how long it asked to
// wait, from Retry-After.
type RateLimited struct{ After time.Duration }

func (e *RateLimited) Error() string {
	return fmt.Sprintf("slack: rate limited, retry after %s", e.After)
}

const maxSlackResponse = 1 << 20

func (c *SlackClient) Post(ctx context.Context, m Message) (string, error) {
	if c.Token == "" {
		return "", errors.New("slack: a bot token is required")
	}
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "https://slack.com/api"
	}
	body, err := json.Marshal(struct {
		Message
		// A report's links are paths on the server, not pages; unfurling
		// them would only fetch nothing.
		UnfurlLinks bool `json:"unfurl_links"`
		UnfurlMedia bool `json:"unfurl_media"`
	}{Message: m})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/chat.postMessage", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("slack: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSlackResponse+1))
	if err != nil {
		return "", fmt.Errorf("slack: %w", err)
	}
	if len(raw) > maxSlackResponse {
		return "", fmt.Errorf("slack: response exceeds %d bytes", maxSlackResponse)
	}
	var answer struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		TS    string `json:"ts"`
	}
	decodeErr := json.Unmarshal(raw, &answer)
	if resp.StatusCode == http.StatusTooManyRequests || answer.Error == "ratelimited" {
		return "", &RateLimited{After: retryAfter(resp.Header.Get("Retry-After"))}
	}
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("slack: status %d", resp.StatusCode)
	}
	if decodeErr != nil {
		return "", fmt.Errorf("slack: answer is not JSON: %w", decodeErr)
	}
	if !answer.OK {
		return "", fmt.Errorf("slack: %s", answer.Error)
	}
	if answer.TS == "" {
		return "", errors.New("slack: posted, but the answer carries no ts")
	}
	return answer.TS, nil
}

func retryAfter(h string) time.Duration {
	if seconds, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return 30 * time.Second
}
