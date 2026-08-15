package oauth2provider

import (
	"context"

	"github.com/patrickkabwe/betterauth-go/provider"
)

// Twitch creates a Twitch OAuth provider.
func Twitch(opts Options) *Provider {
	headers := cloneStringMap(nil)
	headers["Client-Id"] = opts.ClientID
	return New(Config{
		ID: ProviderTwitch, Name: "Twitch",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: []string{"user:read:email"}, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://id.twitch.tv/oauth2/authorize"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://id.twitch.tv/oauth2/token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://api.twitch.tv/helix/users"),
		UserInfoHeaders:       headers,
		RedirectURI:           opts.RedirectURI,
		AuthorizationParams:   opts.AuthorizationParams,
		UsePKCE:               true,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileExtractor:         extractTwitchProfile,
		ProfileMapper:            mapTwitchProfile,
	})
}

func extractTwitchProfile(profile map[string]any) (map[string]any, error) {
	data, ok := profile["data"].([]any)
	if !ok || len(data) == 0 {
		return nil, errInactiveProfile(ProviderTwitch)
	}
	user, ok := data[0].(map[string]any)
	if !ok {
		return nil, errInactiveProfile(ProviderTwitch)
	}
	return user, nil
}

func mapTwitchProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	return provider.OAuthUser{
		ID: stringField(profile, "id"), Name: firstString(stringField(profile, "display_name"), stringField(profile, "login")),
		Email: stringField(profile, "email"), Image: optionalImage(stringField(profile, "profile_image_url")),
		EmailVerified: stringField(profile, "email") != "",
	}, nil
}
