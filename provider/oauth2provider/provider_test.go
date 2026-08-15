package oauth2provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/patrickkabwe/betterauth-go/provider"
)

func TestProviderAuthorizationURLUsesScopesAndPKCE(t *testing.T) {
	p := Spotify(Options{
		ClientID:              "client-id",
		ClientSecret:          "client-secret",
		AuthorizationEndpoint: "https://accounts.example.test/authorize",
		RedirectURI:           "https://app.example.test/callback",
	})

	rawURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "state-1", CodeVerifier: "verifier-1", Scopes: []string{"playlist-read-private"},
	})
	if err != nil {
		t.Fatalf("authorization url: %v", err)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Get("client_id") != "client-id" || query.Get("redirect_uri") != "https://app.example.test/callback" || query.Get("state") != "state-1" {
		t.Fatalf("query=%s", parsed.RawQuery)
	}
	if query.Get("scope") != "user-read-email playlist-read-private" {
		t.Fatalf("scope=%q", query.Get("scope"))
	}
	if query.Get("code_challenge") == "" || query.Get("code_challenge_method") != "S256" {
		t.Fatalf("missing pkce query=%s", parsed.RawQuery)
	}
}

func TestProviderFetchesAndMapsDiscordProfile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer access-token" {
			t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":          "123456789",
			"username":    "ada",
			"global_name": "Ada Lovelace",
			"email":       "ada@example.com",
			"verified":    true,
			"avatar":      "avatar-hash",
		})
	}))
	defer server.Close()

	p := Discord(Options{ClientID: "id", ClientSecret: "secret", UserInfoEndpoint: server.URL})
	info, err := p.GetUserInfo(context.Background(), provider.OAuthTokens{AccessToken: "access-token"})
	if err != nil {
		t.Fatalf("user info: %v", err)
	}
	if info.User.ID != "123456789" || info.User.Name != "Ada Lovelace" || info.User.Email != "ada@example.com" || !info.User.EmailVerified {
		t.Fatalf("user=%+v", info.User)
	}
	if info.User.Image == nil || !strings.Contains(*info.User.Image, "/avatars/123456789/avatar-hash.png") {
		t.Fatalf("image=%v", info.User.Image)
	}
}

func TestNotionExtractsNestedUserProfile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Notion-Version") != "2022-06-28" {
			t.Fatalf("notion version=%q", r.Header.Get("Notion-Version"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"bot": map[string]any{
				"owner": map[string]any{
					"user": map[string]any{
						"id": "user-1", "name": "Notion User", "avatar_url": "https://cdn.example/avatar.png",
						"person": map[string]any{"email": "notion@example.com"},
					},
				},
			},
		})
	}))
	defer server.Close()

	p := Notion(Options{ClientID: "id", ClientSecret: "secret", UserInfoEndpoint: server.URL})
	info, err := p.GetUserInfo(context.Background(), provider.OAuthTokens{AccessToken: "access-token"})
	if err != nil {
		t.Fatalf("user info: %v", err)
	}
	if info.User.ID != "user-1" || info.User.Email != "notion@example.com" || info.User.Name != "Notion User" {
		t.Fatalf("user=%+v", info.User)
	}
}
