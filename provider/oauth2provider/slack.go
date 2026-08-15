package oauth2provider

import (
	"context"

	"github.com/patrickkabwe/betterauth-go/provider"
)

// Slack creates a Slack OpenID Connect provider.
func Slack(opts Options) *Provider {
	return New(Config{
		ID: ProviderSlack, Name: "Slack",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: []string{"openid", "profile", "email"}, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://slack.com/openid/connect/authorize"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://slack.com/api/openid.connect.token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://slack.com/api/openid.connect.userInfo"),
		RedirectURI:           opts.RedirectURI,
		AuthorizationParams:   opts.AuthorizationParams,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileMapper:            mapSlackProfile,
	})
}

func mapSlackProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	return provider.OAuthUser{
		ID:   firstString(stringField(profile, "https://slack.com/user_id"), stringField(profile, "sub")),
		Name: stringField(profile, "name"), Email: stringField(profile, "email"),
		Image:         optionalImage(firstString(stringField(profile, "picture"), stringField(profile, "https://slack.com/user_image_512"))),
		EmailVerified: boolField(profile, "email_verified"),
	}, nil
}
