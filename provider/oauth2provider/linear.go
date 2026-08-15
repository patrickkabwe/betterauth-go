package oauth2provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/patrickkabwe/betterauth-go/provider"
)

// Linear creates a Linear OAuth provider.
func Linear(opts Options) *Provider {
	return New(Config{
		ID: ProviderLinear, Name: "Linear",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: []string{"read"}, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://linear.app/oauth/authorize"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://api.linear.app/oauth/token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://api.linear.app/graphql"),
		UserInfoMethod:        "POST",
		UserInfoBody:          `{"query":"query { viewer { id name email avatarUrl active createdAt updatedAt } }"}`,
		RedirectURI:           opts.RedirectURI,
		AuthorizationParams:   opts.AuthorizationParams,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileExtractor:         linearProfile,
		ProfileMapper:            mapLinearProfile,
	})
}

func linearProfile(raw map[string]any) (map[string]any, error) {
	data := mapField(raw, "data")
	viewer := mapField(data, "viewer")
	if viewer == nil {
		body, _ := json.Marshal(raw)
		return nil, fmt.Errorf("linear viewer profile missing: %s", string(body))
	}
	return viewer, nil
}

func mapLinearProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	return provider.OAuthUser{
		ID: stringField(profile, "id"), Name: stringField(profile, "name"), Email: stringField(profile, "email"),
		Image: optionalImage(stringField(profile, "avatarUrl")), EmailVerified: false,
	}, nil
}
