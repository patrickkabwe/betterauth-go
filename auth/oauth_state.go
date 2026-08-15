package auth

import (
	"encoding/json"
	"errors"
	constants "github.com/patrickkabwe/betterauth-go/constants"
	"time"

	"github.com/patrickkabwe/betterauth-go/internal/id"
	oauth2pkg "github.com/patrickkabwe/betterauth-go/internal/oauth2"
	"github.com/patrickkabwe/betterauth-go/types"
)

type oauthLinkState struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
}

type oauthStatePayload struct {
	CallbackURL    string          `json:"callbackURL"`
	CodeVerifier   string          `json:"codeVerifier"`
	ErrorURL       string          `json:"errorURL,omitempty"`
	NewUserURL     string          `json:"newUserURL,omitempty"`
	Link           *oauthLinkState `json:"link,omitempty"`
	RequestSignUp  bool            `json:"requestSignUp,omitempty"`
	AdditionalData map[string]any  `json:"additionalData,omitempty"`
	OAuthState     string          `json:"oauthState,omitempty"`
	ExpiresAt      time.Time       `json:"expiresAt"`
}

type oauthStateInput struct {
	CallbackURL        string
	ErrorCallbackURL   string
	NewUserCallbackURL string
	Link               *oauthLinkState
	RequestSignUp      bool
	AdditionalData     map[string]any
}

func (a *Auth) generateOAuthState(c *Context, input oauthStateInput) (state string, codeVerifier string, err error) {
	callback := input.CallbackURL
	if callback == "" {
		callback = a.cfg.baseURL
	}
	codeVerifier, err = oauth2pkg.GenerateCodeVerifier()
	if err != nil {
		return "", "", err
	}
	state, err = oauth2pkg.GenerateState()
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	payload := oauthStatePayload{
		CallbackURL:    callback,
		CodeVerifier:   codeVerifier,
		ErrorURL:       input.ErrorCallbackURL,
		NewUserURL:     input.NewUserCallbackURL,
		Link:           input.Link,
		RequestSignUp:  input.RequestSignUp,
		AdditionalData: sanitizeOAuthStateAdditionalData(input.AdditionalData),
		OAuthState:     state,
		ExpiresAt:      now.Add(10 * time.Minute),
	}
	raw, err := marshalOAuthStatePayload(payload)
	if err != nil {
		return "", "", err
	}
	vID, err := id.Generate(32)
	if err != nil {
		return "", "", err
	}
	if err := a.cfg.store.CreateVerification(c.R.Context(), &types.Verification{
		ID: vID, Identifier: constants.VerificationOAuthState + state, Value: string(raw),
		ExpiresAt: payload.ExpiresAt, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		return "", "", err
	}
	return state, codeVerifier, nil
}

func sanitizeOAuthStateAdditionalData(additional map[string]any) map[string]any {
	if len(additional) == 0 {
		return nil
	}
	out := make(map[string]any, len(additional))
	for key, value := range additional {
		if isReservedOAuthStateKey(key) {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func isReservedOAuthStateKey(key string) bool {
	switch key {
	case "callbackURL", "codeVerifier", "errorURL", "newUserURL", "link", "requestSignUp", "expiresAt", "oauthState":
		return true
	default:
		return false
	}
}

func marshalOAuthStatePayload(payload oauthStatePayload) ([]byte, error) {
	data := make(map[string]any, len(payload.AdditionalData)+8)
	for key, value := range payload.AdditionalData {
		data[key] = value
	}
	data["callbackURL"] = payload.CallbackURL
	data["codeVerifier"] = payload.CodeVerifier
	if payload.ErrorURL != "" {
		data["errorURL"] = payload.ErrorURL
	}
	if payload.NewUserURL != "" {
		data["newUserURL"] = payload.NewUserURL
	}
	if payload.Link != nil {
		data["link"] = payload.Link
	}
	if payload.RequestSignUp {
		data["requestSignUp"] = payload.RequestSignUp
	}
	if payload.OAuthState != "" {
		data["oauthState"] = payload.OAuthState
	}
	data["expiresAt"] = payload.ExpiresAt
	return json.Marshal(data)
}

func (a *Auth) parseOAuthState(c *Context, state string) (*oauthStatePayload, error) {
	v, err := a.cfg.store.FindVerificationByIdentifier(c.R.Context(), constants.VerificationOAuthState+state)
	if err != nil {
		return nil, err
	}
	var payload oauthStatePayload
	if err := json.Unmarshal([]byte(v.Value), &payload); err != nil {
		return nil, err
	}
	if err := a.cfg.store.DeleteVerificationByIdentifier(c.R.Context(), constants.VerificationOAuthState+state); err != nil {
		return nil, err
	}
	if time.Now().After(v.ExpiresAt) {
		return nil, errors.New("oauth state expired")
	}
	return &payload, nil
}
