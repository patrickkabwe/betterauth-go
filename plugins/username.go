package plugins

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/types"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.]+$`)

// UsernameValidator validates a username after the configured validation order is applied.
type UsernameValidator func(ctx context.Context, username string) (bool, error)

// DisplayUsernameValidator validates the public display username.
type DisplayUsernameValidator func(ctx context.Context, displayUsername string) (bool, error)

// UsernameNormalization normalizes usernames before lookup.
type UsernameNormalization func(username string) string

// DisplayUsernameNormalization normalizes display usernames before storage.
type DisplayUsernameNormalization func(displayUsername string) string

// UsernameValidationOrder controls whether sign-in validation sees the normalized username.
type UsernameValidationOrder string

const (
	UsernameValidationPreNormalization  UsernameValidationOrder = "pre-normalization"
	UsernameValidationPostNormalization UsernameValidationOrder = "post-normalization"
)

// UsernameOptions configures username sign-in.
type UsernameOptions struct {
	MinUsernameLength              int
	MaxUsernameLength              int
	UsernameValidator              UsernameValidator
	DisplayUsernameValidator       DisplayUsernameValidator
	UsernameNormalization          UsernameNormalization
	DisplayUsernameNormalization   DisplayUsernameNormalization
	DisableUsernameNormalization   bool
	UsernameValidationOrder        UsernameValidationOrder
	DisplayUsernameValidationOrder UsernameValidationOrder
}

type usernameOptionsResolved struct {
	minLen                         int
	maxLen                         int
	validator                      UsernameValidator
	displayValidator               DisplayUsernameValidator
	normalizer                     UsernameNormalization
	displayNormalizer              DisplayUsernameNormalization
	validationOrder                UsernameValidationOrder
	displayUsernameValidationOrder UsernameValidationOrder
}

// Username adds username-based sign-in.
func Username(opts UsernameOptions) auth.Plugin {
	resolved := resolveUsernameOptions(opts)
	return usernamePlugin{
		basePlugin: basePlugin{
			id: constants.PluginUsername,
			routes: []auth.PluginRoute{
				rt(http.MethodPost, "/is-username-available", usernameAvailabilityHandler(resolved)),
				rt(http.MethodPost, "/sign-in/username", usernameSignInHandler(resolved)),
			},
		},
		opts: resolved,
	}
}

type usernamePlugin struct {
	basePlugin
	opts usernameOptionsResolved
}

func (p usernamePlugin) AdditionalUserFields() map[string]auth.AdditionalFieldDef {
	return map[string]auth.AdditionalFieldDef{
		constants.FieldUsername:        {Type: "string"},
		constants.FieldDisplayUsername: {Type: "string"},
	}
}

func (p usernamePlugin) ProcessUserAdditional(c *auth.Context, action string, currentUserID string, fields map[string]any) (map[string]any, *apierror.Error) {
	if len(fields) == 0 {
		return fields, nil
	}
	out := cloneAdditional(fields)
	username, hasUsername := stringField(out, constants.FieldUsername)
	displayUsername, hasDisplayUsername := stringField(out, constants.FieldDisplayUsername)
	if hasUsername {
		if err := p.opts.validateUsername(c, username, http.StatusBadRequest); err != nil {
			return nil, err
		}
		normalizedUsername := p.opts.normalizer(username)
		existing, err := c.Auth.FindUserByAdditional(c.R.Context(), constants.FieldUsername, normalizedUsername)
		if err == nil && (currentUserID == "" || existing.ID != currentUserID) {
			return nil, apierror.WithCode(http.StatusBadRequest, constants.CodeUsernameIsAlreadyTaken)
		}
		if err != nil && !errors.Is(err, berrors.ErrNotFound) {
			return nil, apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError)
		}
		out[constants.FieldUsername] = normalizedUsername
		if action == "create" && !hasDisplayUsername {
			displayUsername = username
			hasDisplayUsername = true
		}
	}
	if hasDisplayUsername {
		if err := p.opts.validateDisplayUsername(c, displayUsername); err != nil {
			return nil, err
		}
		out[constants.FieldDisplayUsername] = p.opts.displayNormalizer(displayUsername)
	}
	return out, nil
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
	displayNormalizer := opts.DisplayUsernameNormalization
	if displayNormalizer == nil {
		displayNormalizer = func(displayUsername string) string { return displayUsername }
	}
	return usernameOptionsResolved{
		minLen:                         minLen,
		maxLen:                         maxLen,
		validator:                      validator,
		displayValidator:               opts.DisplayUsernameValidator,
		normalizer:                     normalizer,
		displayNormalizer:              displayNormalizer,
		validationOrder:                opts.UsernameValidationOrder,
		displayUsernameValidationOrder: opts.DisplayUsernameValidationOrder,
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

func (r usernameOptionsResolved) userInputUsernameToValidate(username string) string {
	if r.validationOrder == UsernameValidationPostNormalization {
		return r.normalizer(username)
	}
	return username
}

func (r usernameOptionsResolved) displayUsernameToValidate(displayUsername string) string {
	if r.displayUsernameValidationOrder == UsernameValidationPostNormalization {
		return r.displayNormalizer(displayUsername)
	}
	return displayUsername
}

func (r usernameOptionsResolved) validateUsername(c *auth.Context, username string, status int) *apierror.Error {
	usernameToValidate := r.userInputUsernameToValidate(username)
	if len(usernameToValidate) < r.minLen {
		return apierror.WithCode(status, constants.CodeUsernameTooShort)
	}
	if len(usernameToValidate) > r.maxLen {
		return apierror.WithCode(status, constants.CodeUsernameTooLong)
	}
	ok, err := r.validator(c.R.Context(), usernameToValidate)
	if err != nil {
		return apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError)
	}
	if !ok {
		return apierror.WithCode(status, constants.CodeInvalidUsername)
	}
	return nil
}

func (r usernameOptionsResolved) validateDisplayUsername(c *auth.Context, displayUsername string) *apierror.Error {
	if r.displayValidator == nil {
		return nil
	}
	ok, err := r.displayValidator(c.R.Context(), r.displayUsernameToValidate(displayUsername))
	if err != nil {
		return apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError)
	}
	if !ok {
		return apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidDisplayUsername)
	}
	return nil
}

func writeUsernameValidation(c *auth.Context, opts usernameOptionsResolved, username string, status int) bool {
	if len(username) < opts.minLen {
		c.WriteError(apierror.WithCode(status, constants.CodeUsernameTooShort))
		return false
	}
	if len(username) > opts.maxLen {
		c.WriteError(apierror.WithCode(status, constants.CodeUsernameTooLong))
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

func usernameAvailabilityHandler(resolved usernameOptionsResolved) func(*auth.Context) {
	return func(c *auth.Context) {
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
	}
}

func usernameSignInHandler(resolved usernameOptionsResolved) func(*auth.Context) {
	return func(c *auth.Context) {
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
	}
}

func cloneAdditional(fields map[string]any) map[string]any {
	out := make(map[string]any, len(fields))
	for key, value := range fields {
		out[key] = value
	}
	return out
}

func stringField(fields map[string]any, key string) (string, bool) {
	value, ok := fields[key]
	if !ok {
		return "", false
	}
	str, ok := value.(string)
	if !ok {
		return "", false
	}
	return str, true
}
