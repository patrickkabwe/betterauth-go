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
		AdditionalData: input.AdditionalData,
		ExpiresAt:      now.Add(10 * time.Minute),
	}
	raw, err := json.Marshal(payload)
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
