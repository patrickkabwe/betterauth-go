package oauth2provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/patrickkabwe/betterauth-go/provider"
)

// GitHub creates a GitHub OAuth provider.
func GitHub(opts Options) *Provider {
	return New(Config{
		ID: ProviderGitHub, Name: "GitHub",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: []string{"read:user", "user:email"}, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://github.com/login/oauth/authorize"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://github.com/login/oauth/access_token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://api.github.com/user"),
		RedirectURI:           opts.RedirectURI,
		Prompt:                opts.Prompt,
		AuthorizationParams:   opts.AuthorizationParams,
		AlwaysSendScope:       true,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              githubUserInfo(opts),
		MapProfileToUser:         opts.MapProfileToUser,
	})
}

func githubUserInfo(opts Options) func(context.Context, provider.OAuthTokens) (*provider.UserInfo, error) {
	if opts.GetUserInfo != nil {
		return opts.GetUserInfo
	}
	userEndpoint := endpoint(opts.UserInfoEndpoint, "https://api.github.com/user")
	emailEndpoint := endpoint(opts.EmailEndpoint, "https://api.github.com/user/emails")
	return func(ctx context.Context, tokens provider.OAuthTokens) (*provider.UserInfo, error) {
		if tokens.AccessToken == "" {
			return nil, fmt.Errorf("github access token missing")
		}
		profile, err := githubFetchMap(ctx, userEndpoint, tokens.AccessToken)
		if err != nil {
			return nil, err
		}
		emails, _ := githubFetchEmails(ctx, emailEndpoint, tokens.AccessToken)
		email := githubSelectedEmail(stringField(profile, "email"), emails)
		verified := githubEmailVerified(email, emails)
		profile["email"] = email
		user := provider.OAuthUser{
			ID: stringField(profile, "id"), Name: firstString(stringField(profile, "name"), stringField(profile, "login")),
			Email: email, Image: optionalImage(stringField(profile, "avatar_url")), EmailVerified: verified,
		}
		if opts.MapProfileToUser != nil {
			mapping, err := opts.MapProfileToUser(ctx, profile)
			if err != nil {
				return nil, err
			}
			user = provider.ApplyOAuthUserMapping(user, mapping)
		}
		return &provider.UserInfo{User: user, Data: profile}, nil
	}
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func githubFetchMap(ctx context.Context, endpoint string, accessToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", defaultUserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github profile failed: status=%d body=%s", resp.StatusCode, string(body))
	}
	var profile map[string]any
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, err
	}
	return profile, nil
}

func githubFetchEmails(ctx context.Context, endpoint string, accessToken string) ([]githubEmail, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", defaultUserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github emails failed: status=%d body=%s", resp.StatusCode, string(body))
	}
	var emails []githubEmail
	if err := json.Unmarshal(body, &emails); err != nil {
		return nil, err
	}
	return emails, nil
}

func githubSelectedEmail(profileEmail string, emails []githubEmail) string {
	if profileEmail != "" {
		return profileEmail
	}
	for _, email := range emails {
		if email.Primary {
			return email.Email
		}
	}
	if len(emails) > 0 {
		return emails[0].Email
	}
	return ""
}

func githubEmailVerified(selectedEmail string, emails []githubEmail) bool {
	for _, email := range emails {
		if email.Email == selectedEmail {
			return email.Verified
		}
	}
	return false
}
