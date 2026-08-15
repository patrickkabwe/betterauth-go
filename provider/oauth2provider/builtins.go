package oauth2provider

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/provider"
)

const (
	ProviderGoogle  = constants.ProviderGoogle
	ProviderGitHub  = constants.ProviderGitHub
	ProviderDiscord = constants.ProviderDiscord
	ProviderDropbox = constants.ProviderDropbox
	ProviderFigma   = constants.ProviderFigma
	ProviderGitLab  = constants.ProviderGitLab
	ProviderNotion  = constants.ProviderNotion
	ProviderSlack   = constants.ProviderSlack
	ProviderSpotify = constants.ProviderSpotify
	ProviderVercel  = constants.ProviderVercel
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
	DisableImplicitSignUp    bool
	DisableSignUp            bool
	OverrideUserInfoOnSignIn bool
	DisableIDTokenSignIn     bool
	GetUserInfo              func(context.Context, provider.OAuthTokens) (*provider.UserInfo, error)
	MapProfileToUser         func(context.Context, map[string]any) (provider.OAuthUserMapping, error)
}

// Discord creates a Discord OAuth provider.
func Discord(opts Options) *Provider {
	return New(Config{
		ID: ProviderDiscord, Name: "Discord",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: []string{"identify", "email"}, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://discord.com/api/oauth2/authorize"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://discord.com/api/oauth2/token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://discord.com/api/users/@me"),
		Prompt:                prompt(opts.Prompt, "none"),
		AuthorizationParams:   opts.AuthorizationParams,
		RedirectURI:           opts.RedirectURI,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileMapper:            mapDiscordProfile,
	})
}

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

// Figma creates a Figma OAuth provider.
func Figma(opts Options) *Provider {
	return New(Config{
		ID: ProviderFigma, Name: "Figma",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: []string{"current_user:read"}, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://www.figma.com/oauth"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://api.figma.com/v1/oauth/token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://api.figma.com/v1/me"),
		RedirectURI:           opts.RedirectURI,
		AuthorizationParams:   opts.AuthorizationParams,
		UsePKCE:               true,
		TokenAuthentication:   provider.OAuthClientAuthenticationBasic,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileMapper:            mapFigmaProfile,
	})
}

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

// Notion creates a Notion OAuth provider.
func Notion(opts Options) *Provider {
	params := cloneStringMap(opts.AuthorizationParams)
	params["owner"] = "user"
	return New(Config{
		ID: ProviderNotion, Name: "Notion",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: nil, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://api.notion.com/v1/oauth/authorize"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://api.notion.com/v1/oauth/token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://api.notion.com/v1/users/me"),
		UserInfoHeaders:       map[string]string{"Notion-Version": "2022-06-28"},
		RedirectURI:           opts.RedirectURI,
		AuthorizationParams:   params,
		TokenAuthentication:   provider.OAuthClientAuthenticationBasic,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileExtractor:         extractNotionUserProfile,
		ProfileMapper:            mapNotionProfile,
	})
}

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

// Vercel creates a Vercel OAuth provider.
func Vercel(opts Options) *Provider {
	return New(Config{
		ID: ProviderVercel, Name: "Vercel",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: nil, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://vercel.com/oauth/authorize"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://api.vercel.com/login/oauth/token"),
		UserInfoEndpoint:      endpoint(opts.UserInfoEndpoint, "https://api.vercel.com/login/oauth/userinfo"),
		RedirectURI:           opts.RedirectURI,
		AuthorizationParams:   opts.AuthorizationParams,
		UsePKCE:               true,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              opts.GetUserInfo,
		MapProfileToUser:         opts.MapProfileToUser,
		ProfileMapper:            mapVercelProfile,
	})
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

func mapDiscordProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	avatar := stringField(profile, "avatar")
	id := stringField(profile, "id")
	image := discordAvatarURL(id, avatar, stringField(profile, "discriminator"))
	return provider.OAuthUser{
		ID: id, Name: firstString(stringField(profile, "global_name"), stringField(profile, "username")),
		Email: stringField(profile, "email"), Image: optionalImage(image), EmailVerified: boolField(profile, "verified"),
	}, nil
}

func mapDropboxProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	name := mapField(profile, "name")
	return provider.OAuthUser{
		ID: stringField(profile, "account_id"), Name: stringField(name, "display_name"),
		Email: stringField(profile, "email"), Image: optionalImage(stringField(profile, "profile_photo_url")),
		EmailVerified: boolField(profile, "email_verified"),
	}, nil
}

func mapFigmaProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	return provider.OAuthUser{
		ID: stringField(profile, "id"), Name: stringField(profile, "handle"),
		Email: stringField(profile, "email"), Image: optionalImage(stringField(profile, "img_url")),
		EmailVerified: false,
	}, nil
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

func extractNotionUserProfile(profile map[string]any) (map[string]any, error) {
	bot, err := requiredProfile(profile, "bot")
	if err != nil {
		return nil, err
	}
	owner, err := requiredProfile(bot, "owner")
	if err != nil {
		return nil, err
	}
	user, err := requiredProfile(owner, "user")
	if err != nil {
		return nil, err
	}
	return user, nil
}

func mapNotionProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	person := mapField(profile, "person")
	return provider.OAuthUser{
		ID: stringField(profile, "id"), Name: stringField(profile, "name"),
		Email: stringField(person, "email"), Image: optionalImage(stringField(profile, "avatar_url")),
		EmailVerified: false,
	}, nil
}

func mapSlackProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	return provider.OAuthUser{
		ID:   firstString(stringField(profile, "https://slack.com/user_id"), stringField(profile, "sub")),
		Name: stringField(profile, "name"), Email: stringField(profile, "email"),
		Image:         optionalImage(firstString(stringField(profile, "picture"), stringField(profile, "https://slack.com/user_image_512"))),
		EmailVerified: boolField(profile, "email_verified"),
	}, nil
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

func mapVercelProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	return provider.OAuthUser{
		ID: stringField(profile, "sub"), Name: firstString(stringField(profile, "name"), stringField(profile, "preferred_username")),
		Email: stringField(profile, "email"), Image: optionalImage(stringField(profile, "picture")),
		EmailVerified: boolField(profile, "email_verified"),
	}, nil
}

func discordAvatarURL(id string, avatar string, discriminator string) string {
	if avatar != "" {
		format := "png"
		if strings.HasPrefix(avatar, "a_") {
			format = "gif"
		}
		return fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.%s", id, avatar, format)
	}
	defaultAvatarNumber := 0
	if discriminator == "0" || discriminator == "" {
		parsed := new(big.Int)
		if _, ok := parsed.SetString(id, 10); ok {
			parsed.Rsh(parsed, 22)
			defaultAvatarNumber = int(new(big.Int).Mod(parsed, big.NewInt(6)).Int64())
		}
	} else {
		parsed, err := strconvAtoi(discriminator)
		if err == nil {
			defaultAvatarNumber = parsed % 5
		}
	}
	return fmt.Sprintf("https://cdn.discordapp.com/embed/avatars/%d.png", defaultAvatarNumber)
}

func firstString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func strconvAtoi(input string) (int, error) {
	value := 0
	for _, char := range input {
		if char < '0' || char > '9' {
			return 0, fmt.Errorf("invalid integer %q", input)
		}
		value = value*10 + int(char-'0')
	}
	return value, nil
}
