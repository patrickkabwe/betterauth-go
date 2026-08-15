package auth_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/plugins"
)

func TestClientSchema(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.AppName = "Test App"
		c.User.AdditionalFields = map[string]auth.AdditionalFieldDef{
			"role": {Type: "string", Required: false},
		}
		c.Plugins = []auth.Plugin{
			plugins.Bearer(plugins.BearerOptions{}),
			plugins.Organization(plugins.OrganizationOptions{}),
		}
	})

	resp, data := doRequest(a, http.MethodGet, "/client-schema", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.StatusCode, data)
	}

	var schema auth.ClientSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.AppName != "Test App" {
		t.Fatalf("appName = %q", schema.AppName)
	}
	if !schema.Features.Bearer {
		t.Fatal("expected bearer feature")
	}
	if schema.User["role"].Type != "string" {
		t.Fatal("missing role field")
	}

	var org *auth.ClientPluginSchema
	for i := range schema.Plugins {
		if schema.Plugins[i].ID == constants.PluginOrganization {
			org = &schema.Plugins[i]
			break
		}
	}
	if org == nil || org.ClientPlugin == nil || org.ClientPlugin.Import != "organizationClient" {
		t.Fatalf("organization client plugin missing: %+v", org)
	}
	for _, endpoint := range org.Endpoints {
		if endpoint.Path == "/organization/add-member" {
			t.Fatalf("server-only organization add-member leaked into plugin schema")
		}
		if isOrganizationTeamEndpoint(endpoint.Path) {
			t.Fatalf("disabled organization team endpoint leaked into plugin schema: %s", endpoint.Path)
		}
	}
	for _, endpoint := range schema.Routes {
		if endpoint.Path == "/organization/add-member" {
			t.Fatalf("server-only organization add-member leaked into route schema")
		}
		if isOrganizationTeamEndpoint(endpoint.Path) {
			t.Fatalf("disabled organization team endpoint leaked into route schema: %s", endpoint.Path)
		}
	}
}

func isOrganizationTeamEndpoint(path string) bool {
	switch path {
	case "/organization/create-team",
		"/organization/remove-team",
		"/organization/update-team",
		"/organization/list-teams",
		"/organization/set-active-team",
		"/organization/list-user-teams",
		"/organization/list-team-members",
		"/organization/add-team-member",
		"/organization/remove-team-member":
		return true
	default:
		return false
	}
}

func TestBearerSetAuthTokenHeader(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Bearer(plugins.BearerOptions{})}
	})

	resp, _ := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "Bearer User", "email": "bearer@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-up status = %d", resp.StatusCode)
	}
	token := resp.Header.Get(constants.HeaderSetAuthToken)
	if token == "" {
		t.Fatal("expected set-auth-token header on sign-up")
	}

	resp, data := doRequestWithHeaders(a, http.MethodGet, "/get-session", nil, nil, map[string]string{
		constants.HeaderAuthorization: constants.TokenTypeBearer + " " + token,
	})
	if resp.StatusCode != http.StatusOK || string(data) == "null" {
		t.Fatalf("bearer session failed: status=%d body=%s", resp.StatusCode, data)
	}
}
