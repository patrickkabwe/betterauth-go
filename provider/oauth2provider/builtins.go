package oauth2provider

import (
	"context"

	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/provider"
)

const (
	ProviderApple     = constants.ProviderApple
	ProviderGoogle    = constants.ProviderGoogle
	ProviderGitHub    = constants.ProviderGitHub
	ProviderDiscord   = constants.ProviderDiscord
	ProviderDropbox   = constants.ProviderDropbox
	ProviderFacebook  = constants.ProviderFacebook
	ProviderFigma     = constants.ProviderFigma
	ProviderGitLab    = constants.ProviderGitLab
	ProviderLinkedIn  = constants.ProviderLinkedIn
	ProviderLinear    = constants.ProviderLinear
	ProviderMicrosoft = constants.ProviderMicrosoft
	ProviderNotion    = constants.ProviderNotion
	ProviderReddit    = constants.ProviderReddit
	ProviderSlack     = constants.ProviderSlack
	ProviderSpotify   = constants.ProviderSpotify
	ProviderTwitter   = constants.ProviderTwitter
	ProviderTwitch    = constants.ProviderTwitch
	ProviderVercel    = constants.ProviderVercel
)

// Options configures one of the built-in OAuth2 providers in this package.
type Options struct {
	ClientID                 string
	ClientSecret             string
	Scopes                   []string
	DisableDefaultScope      bool
	RedirectURI              string
	Prompt                   string
	AuthorizationEndpoint    string
	TokenEndpoint            string
	UserInfoEndpoint         string
	EmailEndpoint            string
	AuthorizationParams      map[string]string
	AccessType               string
	Display                  string
	HD                       string
	Duration                 string
	ConfigID                 string
	DisableImplicitSignUp    bool
	DisableSignUp            bool
	OverrideUserInfoOnSignIn bool
	DisableIDTokenSignIn     bool
	GetUserInfo              func(context.Context, provider.OAuthTokens) (*provider.UserInfo, error)
	MapProfileToUser         func(context.Context, map[string]any) (provider.OAuthUserMapping, error)
}

func endpoint(configured string, defaultEndpoint string) string {
	if configured != "" {
		return configured
	}
	return defaultEndpoint
}

func prompt(configured string, defaultPrompt string) string {
	if configured != "" {
		return configured
	}
	return defaultPrompt
}

func cloneStringMap(input map[string]string) map[string]string {
	output := make(map[string]string, len(input)+1)
	for key, value := range input {
		output[key] = value
	}
	return output
}

func firstString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
