package oauth2provider

import (
	"context"

	"github.com/patrickkabwe/betterauth-go/provider"
)

// Spotify creates a Spotify OAuth provider.
func Spotify(opts Options) *Provider {
	return New(Config{
		ID: ProviderSpotify, Name: "Spotify",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: []string{"user-read-email"}, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://accounts.spotify.com/authorize"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://accounts.spotify.com/api/token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://api.spotify.com/v1/me"),
		RedirectURI:           opts.RedirectURI,
		AuthorizationParams:   opts.AuthorizationParams,
		UsePKCE:               true,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileMapper:            mapSpotifyProfile,
	})
}

func mapSpotifyProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	image := ""
	images, ok := profile["images"].([]any)
	if ok && len(images) > 0 {
		first, ok := images[0].(map[string]any)
		if ok {
			image = stringField(first, "url")
		}
	}
	return provider.OAuthUser{
		ID: stringField(profile, "id"), Name: stringField(profile, "display_name"),
		Email: stringField(profile, "email"), Image: optionalImage(image), EmailVerified: false,
	}, nil
}
