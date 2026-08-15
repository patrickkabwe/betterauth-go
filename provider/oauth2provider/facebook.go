package oauth2provider

import (
	"context"

	"github.com/patrickkabwe/betterauth-go/provider"
)

// Facebook creates a Facebook OAuth provider.
func Facebook(opts Options) *Provider {
	params := cloneStringMap(opts.AuthorizationParams)
	if opts.ConfigID != "" {
		params["config_id"] = opts.ConfigID
	}
	return New(Config{
		ID: ProviderFacebook, Name: "Facebook",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: []string{"email", "public_profile"}, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://www.facebook.com/v24.0/dialog/oauth"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://graph.facebook.com/v24.0/oauth/access_token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://graph.facebook.com/me?fields=id,name,email,picture"),
		RedirectURI:           opts.RedirectURI,
		AuthorizationParams:   params,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileMapper:            mapFacebookProfile,
	})
}

func mapFacebookProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	picture := mapField(profile, "picture")
	data := mapField(picture, "data")
	return provider.OAuthUser{
		ID: stringField(profile, "id"), Name: stringField(profile, "name"), Email: stringField(profile, "email"),
		Image: optionalImage(stringField(data, "url")), EmailVerified: boolField(profile, "email_verified"),
	}, nil
}
