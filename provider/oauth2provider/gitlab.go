package oauth2provider

import (
	"context"

	"github.com/patrickkabwe/betterauth-go/provider"
)

// GitLab creates a GitLab OAuth provider.
func GitLab(opts Options) *Provider {
	return New(Config{
		ID: ProviderGitLab, Name: "GitLab",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: []string{"read_user"}, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://gitlab.com/oauth/authorize"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://gitlab.com/oauth/token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://gitlab.com/api/v4/user"),
		RedirectURI:           opts.RedirectURI,
		AuthorizationParams:   opts.AuthorizationParams,
		UsePKCE:               true,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileMapper:            mapGitLabProfile,
	})
}

func mapGitLabProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	if stringField(profile, "state") != "" && stringField(profile, "state") != "active" {
		return provider.OAuthUser{}, errInactiveProfile(ProviderGitLab)
	}
	return provider.OAuthUser{
		ID: stringField(profile, "id"), Name: firstString(stringField(profile, "name"), stringField(profile, "username")),
		Email: stringField(profile, "email"), Image: optionalImage(stringField(profile, "avatar_url")),
		EmailVerified: boolField(profile, "email_verified"),
	}, nil
}
