package oauth2provider

import (
	"context"

	"github.com/patrickkabwe/betterauth-go/provider"
)

// Figma creates a Figma OAuth provider.
func Figma(opts Options) *Provider {
	return New(Config{
		ID: ProviderFigma, Name: "Figma",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: []string{"current_user:read"}, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://www.figma.com/oauth"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://api.figma.com/v1/oauth/token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://api.figma.com/v1/me"),
		RedirectURI:           opts.RedirectURI,
		AuthorizationParams:   opts.AuthorizationParams,
		UsePKCE:               true,
		TokenAuthentication:   provider.OAuthClientAuthenticationBasic,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileMapper:            mapFigmaProfile,
	})
}

func mapFigmaProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	return provider.OAuthUser{
		ID: stringField(profile, "id"), Name: stringField(profile, "handle"),
		Email: stringField(profile, "email"), Image: optionalImage(stringField(profile, "img_url")),
		EmailVerified: false,
	}, nil
}
