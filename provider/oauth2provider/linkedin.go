package oauth2provider

import (
	"context"

	"github.com/patrickkabwe/betterauth-go/provider"
)

// LinkedIn creates a LinkedIn OpenID Connect provider.
func LinkedIn(opts Options) *Provider {
	return New(Config{
		ID: ProviderLinkedIn, Name: "LinkedIn",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: []string{"openid", "profile", "email"}, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://www.linkedin.com/oauth/v2/authorization"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://www.linkedin.com/oauth/v2/accessToken"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://api.linkedin.com/v2/userinfo"),
		RedirectURI:           opts.RedirectURI,
		AuthorizationParams:   opts.AuthorizationParams,
		UsePKCE:               true,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileMapper:            mapLinkedInProfile,
	})
}

func mapLinkedInProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	return provider.OAuthUser{
		ID: stringField(profile, "sub"), Name: stringField(profile, "name"),
		Email: stringField(profile, "email"), Image: optionalImage(stringField(profile, "picture")),
		EmailVerified: boolField(profile, "email_verified"),
	}, nil
}
