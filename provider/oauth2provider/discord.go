package oauth2provider

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/patrickkabwe/betterauth-go/provider"
)

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

func mapDiscordProfile(_ context.Context, profile map[string]any) (provider.OAuthUser, error) {
	avatar := stringField(profile, "avatar")
	id := stringField(profile, "id")
	image := discordAvatarURL(id, avatar, stringField(profile, "discriminator"))
	return provider.OAuthUser{
		ID: id, Name: firstString(stringField(profile, "global_name"), stringField(profile, "username")),
		Email: stringField(profile, "email"), Image: optionalImage(image), EmailVerified: boolField(profile, "verified"),
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
