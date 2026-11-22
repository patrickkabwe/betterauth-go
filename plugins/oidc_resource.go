package plugins

import (
	"net/http"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/types"
)

func oidcCreateResourceHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthAdmin(c)
		if !ok {
			return
		}
		var r types.OAuthResource
		if err := c.ParseJSON(&r); err != nil || r.Identifier == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "identifier is required"))
			return
		}
		if r.Name == "" {
			r.Name = r.Identifier
		}
		r.ID, _ = id.Generate(32)
		now := time.Now().UTC()
		r.CreatedAt, r.UpdatedAt = now, now
		if r.PolicyVersion == 0 {
			r.PolicyVersion = 1
		}
		if err := ext.CreateOAuthResource(c.R.Context(), &r); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		c.WriteJSON(http.StatusOK, r)
	}
}

func oidcListResourcesHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthAdmin(c)
		if !ok {
			return
		}
		list, err := ext.ListOAuthResources(c.R.Context())
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		c.WriteJSON(http.StatusOK, list)
	}
}

func oidcGetResourceHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthAdmin(c)
		if !ok {
			return
		}
		r, err := ext.FindOAuthResource(c.R.Context(), c.R.URL.Query().Get("identifier"))
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeNotFound))
			return
		}
		c.WriteJSON(http.StatusOK, r)
	}
}

func oidcUpdateResourceHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthAdmin(c)
		if !ok {
			return
		}
		var r types.OAuthResource
		if err := c.ParseJSON(&r); err != nil || r.Identifier == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "identifier is required"))
			return
		}
		if err := ext.UpdateOAuthResource(c.R.Context(), &r); err != nil {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeNotFound))
			return
		}
		updated, _ := ext.FindOAuthResource(c.R.Context(), r.Identifier)
		c.WriteJSON(http.StatusOK, updated)
	}
}

func oidcDeleteResourceHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthAdmin(c)
		if !ok {
			return
		}
		var body struct {
			Identifier string `json:"identifier"`
		}
		if err := c.ParseJSON(&body); err != nil || body.Identifier == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "identifier is required"))
			return
		}
		if err := ext.DeleteOAuthResource(c.R.Context(), body.Identifier); err != nil {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeNotFound))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func oidcLinkClientResourceHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthAdmin(c)
		if !ok {
			return
		}
		var body struct {
			ClientID   string `json:"client_id"`
			ResourceID string `json:"resource_id"`
		}
		if err := c.ParseJSON(&body); err != nil || body.ClientID == "" || body.ResourceID == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "client_id and resource_id are required"))
			return
		}
		linkID, _ := id.Generate(32)
		if err := ext.LinkOAuthClientResource(c.R.Context(), &types.OAuthClientResource{
			ID: linkID, ClientID: body.ClientID, ResourceID: body.ResourceID, CreatedAt: time.Now().UTC(),
		}); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func oidcUnlinkClientResourceHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthAdmin(c)
		if !ok {
			return
		}
		var body struct {
			ClientID   string `json:"client_id"`
			ResourceID string `json:"resource_id"`
		}
		if err := c.ParseJSON(&body); err != nil || body.ClientID == "" || body.ResourceID == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "client_id and resource_id are required"))
			return
		}
		if err := ext.UnlinkOAuthClientResource(c.R.Context(), body.ClientID, body.ResourceID); err != nil {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeNotFound))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func oidcListClientResourcesHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthAdmin(c)
		if !ok {
			return
		}
		list, err := ext.ListOAuthClientResources(c.R.Context(), c.R.URL.Query().Get("client_id"))
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		c.WriteJSON(http.StatusOK, list)
	}
}

// authenticateOAuthClient resolves and authenticates the client from the
// request body (client_id / client_secret). A client with a stored secret must
// present a matching one; a public client (no secret) needs only client_id.
