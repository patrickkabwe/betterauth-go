package plugins

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

const scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"

// SCIMOptions configures SCIM provisioning.
type SCIMOptions struct {
	Token string
}

// SCIM enables SCIM 2.0 user provisioning endpoints.
func SCIM(opts SCIMOptions) auth.Plugin {
	return basePlugin{
		id: constants.PluginSCIM,
		routes: []auth.PluginRoute{
			rt(http.MethodGet, "/scim/v2/ServiceProviderConfig", func(c *auth.Context) {
				if !requireSCIMToken(c, opts.Token) {
					return
				}
				c.WriteJSON(http.StatusOK, map[string]any{
					"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
					"patch":          map[string]bool{"supported": true},
					"bulk":           map[string]bool{"supported": false},
					"filter":         map[string]any{"supported": true, "maxResults": 100},
					"changePassword": map[string]bool{"supported": false},
					"sort":           map[string]bool{"supported": false},
					"etag":           map[string]bool{"supported": false},
					"authenticationSchemes": []map[string]any{{
						"type": "oauthbearertoken", "name": "OAuth Bearer Token", "primary": true,
					}},
				})
			}),
			rt(http.MethodGet, "/scim/v2/ResourceTypes", func(c *auth.Context) {
				if !requireSCIMToken(c, opts.Token) {
					return
				}
				c.WriteJSON(http.StatusOK, scimListResponse([]map[string]any{scimUserResourceType(c)}, 1, 1))
			}),
			rt(http.MethodGet, "/scim/v2/ResourceTypes/User", func(c *auth.Context) {
				if !requireSCIMToken(c, opts.Token) {
					return
				}
				c.WriteJSON(http.StatusOK, scimUserResourceType(c))
			}),
			rt(http.MethodGet, "/scim/v2/Schemas", func(c *auth.Context) {
				if !requireSCIMToken(c, opts.Token) {
					return
				}
				c.WriteJSON(http.StatusOK, scimListResponse([]map[string]any{scimUserSchemaResource()}, 1, 1))
			}),
			rt(http.MethodGet, "/scim/v2/Schemas/"+scimUserSchema, func(c *auth.Context) {
				if !requireSCIMToken(c, opts.Token) {
					return
				}
				c.WriteJSON(http.StatusOK, scimUserSchemaResource())
			}),
			rt(http.MethodGet, "/scim/v2/Schemas/User", func(c *auth.Context) {
				if !requireSCIMToken(c, opts.Token) {
					return
				}
				c.WriteJSON(http.StatusOK, scimUserSchemaResource())
			}),
			rt(http.MethodGet, "/scim/v2/Users", func(c *auth.Context) {
				if !requireSCIMToken(c, opts.Token) {
					return
				}
				users, err := c.Auth.Store().ListUsers(c.R.Context(), store.ListUsersOpts{Limit: 10000})
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				users = filterSCIMUsers(users, c.R.URL.Query().Get("filter"))
				startIndex := scimPositiveInt(c.R.URL.Query().Get("startIndex"), 1)
				count := scimPositiveInt(c.R.URL.Query().Get("count"), len(users))
				resources := make([]map[string]any, 0, len(users))
				for _, user := range scimPageUsers(users, startIndex, count) {
					resources = append(resources, scimUserResource(user))
				}
				c.WriteJSON(http.StatusOK, scimListResponse(resources, len(users), startIndex))
			}),
			rt(http.MethodPost, "/scim/v2/Users", func(c *auth.Context) {
				if !requireSCIMToken(c, opts.Token) {
					return
				}
				var body scimUserBody
				if err := c.ParseJSON(&body); err != nil {
					writeSCIMError(c, http.StatusBadRequest, "invalidValue", "Invalid SCIM user")
					return
				}
				email := body.primaryEmail()
				if email == "" {
					writeSCIMError(c, http.StatusBadRequest, "invalidValue", "SCIM user email is required")
					return
				}
				user, err := c.Auth.CreateUser(c.R.Context(), body.fullName(email), email, nil, nil)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				verified := true
				user, _ = c.Auth.Store().UpdateUser(c.R.Context(), user.ID, store.UserUpdate{EmailVerified: &verified})
				c.WriteJSON(http.StatusCreated, scimUserResource(*user))
			}),
			rt(http.MethodGet, "/scim/v2/Users/{id}", func(c *auth.Context) {
				if !requireSCIMToken(c, opts.Token) {
					return
				}
				user, err := c.Auth.Store().FindUserByID(c.R.Context(), c.Vars["id"])
				if err != nil {
					writeSCIMError(c, http.StatusNotFound, "notFound", "User not found")
					return
				}
				c.WriteJSON(http.StatusOK, scimUserResource(*user))
			}),
			rt(http.MethodPut, "/scim/v2/Users/{id}", func(c *auth.Context) {
				updateSCIMUser(c, opts.Token)
			}),
			rt(http.MethodPatch, "/scim/v2/Users/{id}", func(c *auth.Context) {
				patchSCIMUser(c, opts.Token)
			}),
			rt(http.MethodDelete, "/scim/v2/Users/{id}", func(c *auth.Context) {
				if !requireSCIMToken(c, opts.Token) {
					return
				}
				if err := c.Auth.Store().DeleteUser(c.R.Context(), c.Vars["id"]); err != nil {
					writeSCIMError(c, http.StatusNotFound, "notFound", "User not found")
					return
				}
				c.W.WriteHeader(http.StatusNoContent)
			}),
		},
	}
}

type scimUserBody struct {
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName"`
	Name        scimName    `json:"name"`
	Emails      []scimEmail `json:"emails"`
	Active      *bool       `json:"active"`
}

func scimUserResourceType(c *auth.Context) map[string]any {
	return map[string]any{
		"id":               "User",
		"name":             "User",
		"endpoint":         "/Users",
		"description":      "User Account",
		"schema":           scimUserSchema,
		"schemaExtensions": []any{},
		"meta": map[string]any{
			"location":     c.Auth.BaseURL() + c.Auth.BasePath() + "/scim/v2/ResourceTypes/User",
			"resourceType": "ResourceType",
		},
	}
}

func scimUserSchemaResource() map[string]any {
	return map[string]any{
		"id":          scimUserSchema,
		"name":        "User",
		"description": "User Account",
		"attributes": []map[string]any{
			{"name": "userName", "type": "string", "multiValued": false, "required": true, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "server"},
			{"name": "name", "type": "complex", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default"},
			{"name": "displayName", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default"},
			{"name": "emails", "type": "complex", "multiValued": true, "required": false, "mutability": "readWrite", "returned": "default"},
			{"name": "active", "type": "boolean", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default"},
		},
	}
}

func scimListResponse(resources []map[string]any, total int, startIndex int) map[string]any {
	return map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": total,
		"startIndex":   startIndex,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	}
}

func scimPositiveInt(value string, fallback int) int {
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return fallback
	}
	return parsed
}

func filterSCIMUsers(users []types.User, filter string) []types.User {
	field, value, ok := parseSCIMFilter(filter)
	if !ok {
		return users
	}
	out := make([]types.User, 0, len(users))
	for _, user := range users {
		switch field {
		case "username", "userName":
			if strings.EqualFold(user.Email, value) {
				out = append(out, user)
			}
		case "id":
			if user.ID == value {
				out = append(out, user)
			}
		}
	}
	return out
}

func parseSCIMFilter(filter string) (string, string, bool) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return "", "", false
	}
	parts := strings.SplitN(filter, " eq ", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	field := strings.TrimSpace(parts[0])
	value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
	if field == "" || value == "" {
		return "", "", false
	}
	return field, value, true
}

func scimPageUsers(users []types.User, startIndex int, count int) []types.User {
	if len(users) == 0 {
		return nil
	}
	start := startIndex - 1
	if start >= len(users) {
		return nil
	}
	end := start + count
	if end > len(users) {
		end = len(users)
	}
	return users[start:end]
}

type scimName struct {
	Formatted  string `json:"formatted"`
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
	Type    string `json:"type"`
}

func (b scimUserBody) primaryEmail() string {
	for _, email := range b.Emails {
		if email.Primary && email.Value != "" {
			return strings.ToLower(email.Value)
		}
	}
	for _, email := range b.Emails {
		if email.Value != "" {
			return strings.ToLower(email.Value)
		}
	}
	return strings.ToLower(b.UserName)
}

func (b scimUserBody) fullName(fallback string) string {
	if b.Name.Formatted != "" {
		return b.Name.Formatted
	}
	name := strings.TrimSpace(strings.TrimSpace(b.Name.GivenName) + " " + strings.TrimSpace(b.Name.FamilyName))
	if name != "" {
		return name
	}
	if b.DisplayName != "" {
		return b.DisplayName
	}
	return fallback
}

func updateSCIMUser(c *auth.Context, token string) {
	if !requireSCIMToken(c, token) {
		return
	}
	var body scimUserBody
	if err := c.ParseJSON(&body); err != nil {
		writeSCIMError(c, http.StatusBadRequest, "invalidValue", "Invalid SCIM user")
		return
	}
	update := store.UserUpdate{}
	name := body.fullName("")
	if name != "" {
		update.Name = &name
	}
	if email := body.primaryEmail(); email != "" {
		update.Email = &email
	}
	user, err := c.Auth.Store().UpdateUser(c.R.Context(), c.Vars["id"], update)
	if err != nil {
		writeSCIMError(c, http.StatusNotFound, "notFound", "User not found")
		return
	}
	c.WriteJSON(http.StatusOK, scimUserResource(*user))
}

func patchSCIMUser(c *auth.Context, token string) {
	if !requireSCIMToken(c, token) {
		return
	}
	var body struct {
		Operations []struct {
			Op    string          `json:"op"`
			Path  string          `json:"path"`
			Value json.RawMessage `json:"value"`
		} `json:"Operations"`
	}
	if err := c.ParseJSON(&body); err != nil {
		writeSCIMError(c, http.StatusBadRequest, "invalidValue", "Invalid SCIM patch")
		return
	}
	update := store.UserUpdate{Additional: map[string]any{}}
	for _, op := range body.Operations {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			continue
		}
		path := strings.ToLower(op.Path)
		switch path {
		case "name.formatted", "displayname":
			var value string
			_ = json.Unmarshal(op.Value, &value)
			if value != "" {
				update.Name = &value
			}
		case "active":
			var active bool
			_ = json.Unmarshal(op.Value, &active)
			update.Additional["active"] = active
		}
	}
	user, err := c.Auth.Store().UpdateUser(c.R.Context(), c.Vars["id"], update)
	if err != nil {
		writeSCIMError(c, http.StatusNotFound, "notFound", "User not found")
		return
	}
	c.WriteJSON(http.StatusOK, scimUserResource(*user))
}

func requireSCIMToken(c *auth.Context, token string) bool {
	if token == "" {
		writeSCIMError(c, http.StatusUnauthorized, "invalidToken", "SCIM token is required")
		return false
	}
	authHeader := c.R.Header.Get(constants.HeaderAuthorization)
	prefix := constants.TokenTypeBearer + " "
	if len(authHeader) <= len(prefix) || !strings.EqualFold(authHeader[:len(prefix)], prefix) || authHeader[len(prefix):] != token {
		writeSCIMError(c, http.StatusUnauthorized, "invalidToken", "Invalid SCIM token")
		return false
	}
	return true
}

func scimUserResource(user types.User) map[string]any {
	active := true
	if user.Additional != nil {
		if value, ok := user.Additional["active"].(bool); ok {
			active = value
		}
	}
	return map[string]any{
		"schemas":     []string{scimUserSchema},
		"id":          user.ID,
		"userName":    user.Email,
		"displayName": user.Name,
		"active":      active,
		"name": map[string]any{
			"formatted": user.Name,
		},
		"emails": []map[string]any{{
			"value": user.Email, "primary": true, "type": "work",
		}},
		"meta": map[string]any{"resourceType": "User"},
	}
}

func writeSCIMError(c *auth.Context, status int, scimType string, detail string) {
	c.W.Header().Set(constants.HeaderContentType, "application/scim+json")
	c.W.WriteHeader(status)
	_ = json.NewEncoder(c.W).Encode(map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":   http.StatusText(status),
		"scimType": scimType,
		"detail":   detail,
	})
}
