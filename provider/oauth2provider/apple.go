package oauth2provider

import (
	"context"
	"fmt"

	"github.com/patrickkabwe/betterauth-go/internal/jwt"
	"github.com/patrickkabwe/betterauth-go/provider"
)

// Apple creates an Apple OAuth provider.
func Apple(opts Options) *Provider {
	return appleProvider(opts)
}

// AppleWithIDToken creates an Apple OAuth provider that supports native ID-token sign-in.
func AppleWithIDToken(opts Options) *IDTokenProvider {
	return &IDTokenProvider{Provider: appleProvider(opts), verifyIDToken: appleIDTokenVerifier(opts)}
}

func appleProvider(opts Options) *Provider {
	return New(Config{
		ID: ProviderApple, Name: "Apple",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: []string{"email", "name"}, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://appleid.apple.com/auth/authorize"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://appleid.apple.com/auth/token"),
		ResponseType:          "code id_token",
		ResponseMode:          "form_post",
		RedirectURI:           opts.RedirectURI,
		AuthorizationParams:   opts.AuthorizationParams,
		UsePKCE:               true,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              appleUserInfo(opts),
		MapProfileToUser:         opts.MapProfileToUser,
	})
}

func appleUserInfo(opts Options) func(context.Context, provider.OAuthTokens) (*provider.UserInfo, error) {
	if opts.GetUserInfo != nil {
		return opts.GetUserInfo
	}
	return func(ctx context.Context, tokens provider.OAuthTokens) (*provider.UserInfo, error) {
		if tokens.IDToken == "" {
			return nil, fmt.Errorf("apple id_token missing")
		}
		claims, err := jwt.DecodePayload(tokens.IDToken)
		if err != nil {
			return nil, err
		}
		name := stringField(claims, "name")
		if name == "" {
			name = stringField(tokens.User, "name")
		}
		user := provider.OAuthUser{
			ID: stringField(claims, "sub"), Name: name, Email: stringField(claims, "email"),
			EmailVerified: boolLikeField(claims, "email_verified"),
		}
		if opts.MapProfileToUser != nil {
			mapping, err := opts.MapProfileToUser(ctx, claims)
			if err != nil {
				return nil, err
			}
			user = provider.ApplyOAuthUserMapping(user, mapping)
		}
		return &provider.UserInfo{User: user, Data: claims}, nil
	}
}

func appleIDTokenVerifier(opts Options) func(context.Context, string, string) (bool, error) {
	if opts.DisableIDTokenSignIn {
		return func(context.Context, string, string) (bool, error) {
			return false, nil
		}
	}
	return func(context.Context, string, string) (bool, error) {
		return false, nil
	}
}
