package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ba "github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/client"
	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/store/memory"
)

func TestGoClientGetSessionBearer(t *testing.T) {
	a, err := ba.New(ba.Config{
		Secret:  "test-secret-key-for-cookie-signing",
		BaseURL: "http://localhost:8080",
		Store:   memory.New(),
		Plugins: []ba.Plugin{plugins.Bearer(plugins.BearerOptions{})},
	})
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", a.Handler()))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	signUpReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/sign-up/email", strings.NewReader(`{"name":"Go","email":"go@example.com","password":"password123"}`))
	signUpReq.Header.Set("Content-Type", "application/json")
	signUpResp, err := http.DefaultClient.Do(signUpReq)
	if err != nil {
		t.Fatal(err)
	}
	token := signUpResp.Header.Get("set-auth-token")
	signUpResp.Body.Close()
	if token == "" {
		t.Fatal("missing set-auth-token")
	}

	cl := client.New(srv.URL, client.WithBearerToken(token))
	sess, err := cl.GetSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sess == nil || sess.User.Email != "go@example.com" {
		t.Fatalf("session = %+v", sess)
	}

	raw, err := cl.FetchSchema(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["version"] != float64(1) {
		t.Fatalf("schema version = %v", schema["version"])
	}
}
