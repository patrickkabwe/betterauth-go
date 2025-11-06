// Package client provides a server-side Better Auth HTTP client compatible with
// better-auth/client (getSession with cookies or Authorization: Bearer).
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SessionPayload matches the Better Auth get-session response shape.
type SessionPayload struct {
	Session struct {
		ID        string    `json:"id"`
		UserID    string    `json:"userId"`
		ExpiresAt time.Time `json:"expiresAt"`
		Token     string    `json:"token,omitempty"`
	} `json:"session"`
	User struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
		Image string `json:"image,omitempty"`
	} `json:"user"`
}

// Client calls Better Auth endpoints from Go services (SSR, workers, CLI).
type Client struct {
	baseURL    string
	bearer     string
	cookie     string
	httpClient *http.Client
}

// Option configures the client.
type Option func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) { cl.httpClient = c }
}

// WithBearerToken sets Authorization: Bearer for stateless/mobile clients.
func WithBearerToken(token string) Option {
	return func(cl *Client) { cl.bearer = token }
}

// WithCookie sets the session cookie value (signed or raw token).
func WithCookie(sessionCookie string) Option {
	return func(cl *Client) { cl.cookie = sessionCookie }
}

// New creates a client. baseURL is the auth server root (e.g. http://localhost:8080).
func New(baseURL string, opts ...Option) *Client {
	cl := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: http.DefaultClient,
	}
	for _, o := range opts {
		o(cl)
	}
	return cl
}

// GetSession fetches the current session via GET /api/auth/get-session.
func (c *Client) GetSession(ctx context.Context) (*SessionPayload, error) {
	return c.GetSessionAt(ctx, "/api/auth/get-session")
}

// GetSessionAt fetches session from a custom path (when basePath differs).
func (c *Client) GetSessionAt(ctx context.Context, path string) (*SessionPayload, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	c.applyAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get-session: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		return nil, nil
	}

	var out SessionPayload
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// FetchSchema downloads GET /client-schema for codegen and client plugin pairing.
func (c *Client) FetchSchema(ctx context.Context) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/auth/client-schema", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client-schema: status %d", resp.StatusCode)
	}
	return json.RawMessage(body), nil
}

func (c *Client) applyAuth(req *http.Request) {
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}
	req.Header.Set("Accept", "application/json")
}
