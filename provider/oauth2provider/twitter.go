package oauth2provider

import (
	"context"

	"github.com/patrickkabwe/betterauth-go/provider"
)

// Twitter creates a Twitter/X OAuth provider.
func Twitter(opts Options) *Provider {
	return New(Config{
		ID: ProviderTwitter, Name: "Twitter",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: []string{"users.read", "tweet.read", "offline.access", "users.email"}, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://x.com/i/oauth2/authorize"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://api.x.com/2/oauth2/token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://api.x.com/2/users/me?user.fields=profile_image_url"),
		TokenAuthentication:   provider.OAuthClientAuthenticationBasic,
		RedirectURI:           opts.RedirectURI,
		AuthorizationParams:   opts.AuthorizationParams,
		UsePKCE:               true,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileExtractor:         twitterProfile,
		ProfileMapper:            mapTwitterProfile,
	})
}

func twitterProfile(raw map[string]any) (map[string]any, error) {
	return requiredProfile(raw, "data")
}

func mapTwitterProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	email := firstString(stringField(profile, "email"), stringField(profile, "username"))
	return provider.OAuthUser{
		ID: stringField(profile, "id"), Name: stringField(profile, "name"), Email: email,
		Image: optionalImage(stringField(profile, "profile_image_url")), EmailVerified: false,
	}, nil
}
