package oauth2provider

import (
	"context"
	"strings"

	"github.com/patrickkabwe/betterauth-go/provider"
)

// Reddit creates a Reddit OAuth provider.
func Reddit(opts Options) *Provider {
	params := cloneStringMap(opts.AuthorizationParams)
	if opts.Duration != "" {
		params["duration"] = opts.Duration
	}
	return New(Config{
		ID: ProviderReddit, Name: "Reddit",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: []string{"identity"}, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://www.reddit.com/api/v1/authorize"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://www.reddit.com/api/v1/access_token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://oauth.reddit.com/api/v1/me"),
		TokenAuthentication:   provider.OAuthClientAuthenticationBasic,
		RedirectURI:           opts.RedirectURI,
		AuthorizationParams:   params,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileMapper:            mapRedditProfile,
	})
}

func mapRedditProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	id := stringField(profile, "id")
	email := id + "@reddit.invalid"
	image := strings.Split(stringField(profile, "icon_img"), "?")[0]
	return provider.OAuthUser{
		ID: id, Name: stringField(profile, "name"), Email: email,
		Image: optionalImage(image), EmailVerified: false,
	}, nil
}
