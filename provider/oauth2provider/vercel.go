package oauth2provider

import (
	"context"

	"github.com/patrickkabwe/betterauth-go/provider"
)

// Vercel creates a Vercel OAuth provider.
func Vercel(opts Options) *Provider {
	return New(Config{
		ID: ProviderVercel, Name: "Vercel",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: nil, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://vercel.com/oauth/authorize"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://api.vercel.com/login/oauth/token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://api.vercel.com/login/oauth/userinfo"),
		RedirectURI:           opts.RedirectURI,
		AuthorizationParams:   opts.AuthorizationParams,
		UsePKCE:               true,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileMapper:            mapVercelProfile,
	})
}

func mapVercelProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	return provider.OAuthUser{
		ID: stringField(profile, "sub"), Name: firstString(stringField(profile, "name"), stringField(profile, "preferred_username")),
		Email: stringField(profile, "email"), Image: optionalImage(stringField(profile, "picture")),
		EmailVerified: boolField(profile, "email_verified"),
	}, nil
}
