package plugins

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/types"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.]+$`)

// UsernameValidator validates a username after the configured validation order is applied.
type UsernameValidator func(ctx context.Context, username string) (bool, error)

// UsernameNormalization normalizes usernames before lookup.
type UsernameNormalization func(username string) string

// UsernameValidationOrder controls whether sign-in validation sees the normalized username.
type UsernameValidationOrder string

const (
	UsernameValidationPreNormalization  UsernameValidationOrder = "pre-normalization"
	UsernameValidationPostNormalization UsernameValidationOrder = "post-normalization"
)

// UsernameOptions configures username sign-in.
type UsernameOptions struct {
	MinUsernameLength            int
	MaxUsernameLength            int
	UsernameValidator            UsernameValidator
	UsernameNormalization        UsernameNormalization
	DisableUsernameNormalization bool
	UsernameValidationOrder      UsernameValidationOrder
}

type usernameOptionsResolved struct {
	minLen          int
	maxLen          int
	validator       UsernameValidator
	normalizer      UsernameNormalization
	validationOrder UsernameValidationOrder
}

// Username adds username-based sign-in.
func Username(opts UsernameOptions) auth.Plugin {
	resolved := resolveUsernameOptions(opts)
	return basePlugin{
		id: constants.PluginUsername,
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/is-username-available", func(c *auth.Context) {
				var body struct {
					Username string `json:"username"`
				}
				if err := c.ParseJSON(&body); err != nil || body.Username == "" {
					c.WriteError(apierror.WithCode(http.StatusUnprocessableEntity, constants.CodeInvalidUsername))
					return
				}
				if !writeUsernameValidation(c, resolved, body.Username, http.StatusUnprocessableEntity) {
					return
				}
				_, err := c.Auth.FindUserByAdditional(c.R.Context(), constants.FieldUsername, resolved.normalizer(body.Username))
				c.WriteJSON(http.StatusOK, map[string]bool{"available": err != nil})
			}),
			rt(http.MethodPost, "/sign-in/username", func(c *auth.Context) {
				var body struct {
					Username    string `json:"username"`
					Password    string `json:"password"`
					CallbackURL string `json:"callbackURL"`
					RememberMe  *bool  `json:"rememberMe"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
				if body.Username == "" || body.Password == "" {
					c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeInvalidEmailOrPassword, constants.MsgInvalidCredentials))
					return
				}
				usernameToValidate := resolved.signInUsernameToValidate(body.Username)
				if !writeUsernameValidation(c, resolved, usernameToValidate, http.StatusUnprocessableEntity) {
					return
				}
				username := resolved.normalizer(body.Username)
				user, err := c.Auth.FindUserByAdditional(c.R.Context(), constants.FieldUsername, username)
				if err != nil {
					c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeInvalidEmailOrPassword, constants.MsgInvalidCredentials))
					return
				}
				account, err := c.Auth.Store().FindAccountByUserAndProvider(c.R.Context(), user.ID, constants.ProviderCredential)
				if err != nil || account.Password == "" {
					c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeInvalidEmailOrPassword, constants.MsgInvalidCredentials))
					return
				}
				ok, _ := c.Auth.VerifyPassword(account.Password, body.Password)
				if !ok {
					c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeInvalidEmailOrPassword, constants.MsgInvalidCredentials))
					return
				}
				allowed, err := c.Auth.AllowSignInWithEmailVerification(c, user, body.CallbackURL)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				if !allowed {
					c.WriteError(apierror.WithCode(http.StatusForbidden, apierror.CodeEmailNotVerified))
					return
				}
				remember := true
				if body.RememberMe != nil {
					remember = *body.RememberMe
				}
				sess, err := c.Auth.NewSession(c, user.ID, remember)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeFailedToCreateSession))
					return
				}
				if body.CallbackURL != "" {
					c.W.Header().Set("Location", body.CallbackURL)
				}
				c.WriteJSON(http.StatusOK, types.SignInResponse{
					Redirect: body.CallbackURL != "",
					Token:    sess.Token,
					URL:      body.CallbackURL,
					User:     *user,
				})
			}),
		},
	}
}

func resolveUsernameOptions(opts UsernameOptions) usernameOptionsResolved {
	minLen := opts.MinUsernameLength
	if minLen == 0 {
		minLen = 3
	}
	maxLen := opts.MaxUsernameLength
	if maxLen == 0 {
		maxLen = 30
	}
	validator := opts.UsernameValidator
	if validator == nil {
		validator = defaultUsernameValidator
	}
	normalizer := opts.UsernameNormalization
	if opts.DisableUsernameNormalization {
		normalizer = func(username string) string { return username }
	}
	if normalizer == nil {
		normalizer = strings.ToLower
	}
	return usernameOptionsResolved{
		minLen:          minLen,
		maxLen:          maxLen,
		validator:       validator,
		normalizer:      normalizer,
		validationOrder: opts.UsernameValidationOrder,
	}
}

func defaultUsernameValidator(_ context.Context, username string) (bool, error) {
	return usernamePattern.MatchString(username), nil
}

func (r usernameOptionsResolved) signInUsernameToValidate(username string) string {
	if r.validationOrder == UsernameValidationPostNormalization {
		return username
	}
	return r.normalizer(username)
}

func writeUsernameValidation(c *auth.Context, opts usernameOptionsResolved, username string, status int) bool {
	if len(username) < opts.minLen || len(username) > opts.maxLen {
		c.WriteError(apierror.WithCode(status, constants.CodeInvalidUsername))
		return false
	}
	ok, err := opts.validator(c.R.Context(), username)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	if !ok {
		c.WriteError(apierror.WithCode(status, constants.CodeInvalidUsername))
		return false
	}
	return true
}
