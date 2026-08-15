package oauth2provider

import (
	"context"

	"github.com/patrickkabwe/betterauth-go/provider"
)

// Microsoft creates a Microsoft identity platform OpenID Connect provider.
func Microsoft(opts Options) *Provider {
	return New(Config{
		ID: ProviderMicrosoft, Name: "Microsoft",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: []string{"openid", "profile", "email"}, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://login.microsoftonline.com/common/oauth2/v2.0/token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://graph.microsoft.com/oidc/userinfo"),
		RedirectURI:           opts.RedirectURI,
		Prompt:                opts.Prompt,
		AuthorizationParams:   opts.AuthorizationParams,
		UsePKCE:               true,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileMapper:            mapMicrosoftProfile,
	})
}

func mapMicrosoftProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	return provider.OAuthUser{
		ID:    firstString(stringField(profile, "sub"), stringField(profile, "oid")),
		Name:  firstString(stringField(profile, "name"), stringField(profile, "preferred_username")),
		Email: firstString(stringField(profile, "email"), stringField(profile, "preferred_username")),
		Image: optionalImage(stringField(profile, "picture")), EmailVerified: true,
	}, nil
}
