package oauth2provider

import (
	"context"

	"github.com/patrickkabwe/betterauth-go/provider"
)

// Notion creates a Notion OAuth provider.
func Notion(opts Options) *Provider {
	params := cloneStringMap(opts.AuthorizationParams)
	params["owner"] = "user"
	return New(Config{
		ID: ProviderNotion, Name: "Notion",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: nil, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://api.notion.com/v1/oauth/authorize"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://api.notion.com/v1/oauth/token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://api.notion.com/v1/users/me"),
		UserInfoHeaders:       map[string]string{"Notion-Version": "2022-06-28"},
		RedirectURI:           opts.RedirectURI,
		AuthorizationParams:   params,
		TokenAuthentication:   provider.OAuthClientAuthenticationBasic,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileExtractor:         extractNotionUserProfile,
		ProfileMapper:            mapNotionProfile,
	})
}

func extractNotionUserProfile(profile map[string]any) (map[string]any, error) {
	bot, err := requiredProfile(profile, "bot")
	if err != nil {
		return nil, err
	}
	owner, err := requiredProfile(bot, "owner")
	if err != nil {
		return nil, err
	}
	user, err := requiredProfile(owner, "user")
	if err != nil {
		return nil, err
	}
	return user, nil
}

func mapNotionProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	person := mapField(profile, "person")
	return provider.OAuthUser{
		ID: stringField(profile, "id"), Name: stringField(profile, "name"),
		Email: stringField(person, "email"), Image: optionalImage(stringField(profile, "avatar_url")),
		EmailVerified: false,
	}, nil
}
