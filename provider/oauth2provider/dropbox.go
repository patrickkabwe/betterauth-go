package oauth2provider

import (
	"context"
	"net/http"

	"github.com/patrickkabwe/betterauth-go/provider"
)

// Dropbox creates a Dropbox OAuth provider.
func Dropbox(opts Options) *Provider {
	return New(Config{
		ID: ProviderDropbox, Name: "Dropbox",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: []string{"account_info.read"}, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://www.dropbox.com/oauth2/authorize"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://api.dropboxapi.com/oauth2/token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://api.dropboxapi.com/2/users/get_current_account"),
		UserInfoMethod:        http.MethodPost,
		RedirectURI:           opts.RedirectURI,
		AuthorizationParams:   opts.AuthorizationParams,
		UsePKCE:               true,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileMapper:            mapDropboxProfile,
	})
}

func mapDropboxProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	name := mapField(profile, "name")
	return provider.OAuthUser{
		ID: stringField(profile, "account_id"), Name: stringField(name, "display_name"),
		Email: stringField(profile, "email"), Image: optionalImage(stringField(profile, "profile_photo_url")),
		EmailVerified: boolField(profile, "email_verified"),
	}, nil
}
