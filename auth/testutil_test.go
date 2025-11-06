package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/store/memory"
	"github.com/patrickkabwe/betterauth-go/types"
)

type sentMail struct {
	mu    sync.Mutex
	items []string
}

func (m *sentMail) record(url string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = append(m.items, url)
}

func newTestAuth(opts ...func(*auth.Config)) *auth.Auth {
	cfg := auth.Config{
		Secret:  "test-secret-key-for-cookie-signing",
		BaseURL: "http://localhost:8080",
		TrustedOrigins: []string{
			"http://localhost:3000",
		},
		Store: memory.New(),
	}
	for _, fn := range opts {
		fn(&cfg)
	}
	a, err := auth.New(cfg)
	if err != nil {
		panic(err)
	}
	return a
}

func doRequest(a *auth.Auth, method, path string, body any, cookies []*http.Cookie) (*http.Response, []byte) {
	return doRequestWithHeaders(a, method, path, body, cookies, nil)
}

func doRequestWithHeaders(a *auth.Auth, method, path string, body any, cookies []*http.Cookie, headers map[string]string) (*http.Response, []byte) {
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}

	req := httptest.NewRequest(method, "http://example.com/api/auth"+path, reader)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}

	rr := httptest.NewRecorder()
	http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path
		if i := strings.Index(path, "?"); i >= 0 {
			r.URL.RawQuery = path[i+1:]
			clean = path[:i]
		}
		r.URL.Path = clean
		a.Handler().ServeHTTP(w, r)
	}).ServeHTTP(rr, req)

	resp := rr.Result()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

func signUp(t testingT, a *auth.Auth, email string) []*http.Cookie {
	t.Helper()
	resp, data := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name":     "Test User",
		"email":    email,
		"password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-up status = %d body=%s", resp.StatusCode, data)
	}
	return resp.Cookies()
}

type testingT interface {
	Helper()
	Fatalf(string, ...any)
}

func createDeleteVerificationToken(t testingT, a *auth.Auth, userID string) string {
	t.Helper()
	token, err := id.Generate(32)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	now := time.Now()
	vID, _ := id.Generate(32)
	st := a.Store().(*memory.Store)
	_ = st.CreateVerification(context.Background(), &types.Verification{
		ID: vID, Identifier: "delete-account:" + token, Value: userID,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	})
	return token
}
