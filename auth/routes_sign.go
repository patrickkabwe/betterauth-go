package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/cookie"
	"github.com/patrickkabwe/betterauth-go/internal/crypto"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/types"
)

type signUpBody struct {
	Name        string  `json:"name"`
	Email       string  `json:"email"`
	Password    string  `json:"password"`
	Image       *string `json:"image"`
	CallbackURL string  `json:"callbackURL"`
	RememberMe  *bool   `json:"rememberMe"`
}

func handleSignUpEmail(c *Context) {
	if c.Auth.cfg.disableSignUp {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeEmailPasswordSignUpDisabled))
		return
	}

	var raw map[string]json.RawMessage
	var body signUpBody
	if err := c.ParseJSON(&raw); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeInvalidEmail, constants.MsgInvalidRequestBody))
		return
	}
	if err := decodeRawBody(raw, &body); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeInvalidEmail, constants.MsgInvalidRequestBody))
		return
	}
	if err := validateSignUpInput(c, body.Name, body.Email, body.Password); err != nil {
		c.WriteError(err)
		return
	}
	additional, fieldErr := parseAdditionalUserInput(c.Auth.cfg.user.additionalFields, raw, "create")
	if fieldErr != nil {
		c.WriteError(fieldErr)
		return
	}
	additional, fieldErr = runUserAdditionalProcessors(c, "create", "", additional)
	if fieldErr != nil {
		c.WriteError(fieldErr)
		return
	}

	email := strings.ToLower(strings.TrimSpace(body.Email))
	_, err := c.Auth.cfg.store.FindUserByEmail(c.R.Context(), email)
	if err == nil {
		handleDuplicateSignUp(c, body, email)
		return
	}
	if !errors.Is(err, berrors.ErrNotFound) {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}

	user, account, err := createUserWithCredential(c, body.Name, email, body.Password, body.Image, additional)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusUnprocessableEntity, apierror.CodeFailedToCreateUser))
		return
	}
	if shouldSendSignUpVerification(c.Auth.cfg) {
		if err := sendVerificationEmailToUser(c, user, body.CallbackURL); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
	}
	if err := runSignUpVerificationPlugins(c, c.Auth.cfg.plugins, user); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}

	if !c.Auth.cfg.emailPassword.autoSignIn {
		c.WriteJSON(http.StatusOK, types.SignUpResponse{Token: nil, User: toUserResponse(user)})
		return
	}

	rememberMe := true
	if body.RememberMe != nil {
		rememberMe = *body.RememberMe
	}

	sess, err := c.Auth.createSession(c, user.ID, rememberMe)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusUnauthorized, apierror.CodeFailedToCreateSession))
		return
	}
	_ = account
	token := sess.Token
	c.WriteJSON(http.StatusOK, types.SignUpResponse{Token: &token, User: toUserResponse(user)})
}

func shouldSendSignUpVerification(cfg resolved) bool {
	if cfg.emailVerification.sendVerificationEmail == nil {
		if _, ok := emailVerificationOverridePlugin(cfg.plugins); !ok {
			return false
		}
	}
	if cfg.emailVerification.sendOnSignUp != nil {
		return *cfg.emailVerification.sendOnSignUp
	}
	return cfg.emailPassword.requireEmailVerification
}

func handleDuplicateSignUp(c *Context, body signUpBody, email string) {
	if c.Auth.cfg.emailPassword.requireEmailVerification || !c.Auth.cfg.emailPassword.autoSignIn {
		if _, err := c.Auth.cfg.hasher.Hash(body.Password); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
		syntheticID, err := id.Generate(32)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
		now := time.Now()
		c.WriteJSON(http.StatusOK, types.SignUpResponse{
			Token: nil,
			User: types.User{
				ID:            syntheticID,
				Name:          body.Name,
				Email:         email,
				EmailVerified: false,
				Image:         body.Image,
				CreatedAt:     now,
				UpdatedAt:     now,
			},
		})
		return
	}
	c.WriteError(apierror.WithCode(http.StatusUnprocessableEntity, apierror.CodeFailedToCreateUser))
}

type signInBody struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	CallbackURL string `json:"callbackURL"`
	RememberMe  *bool  `json:"rememberMe"`
}

func handleSignInEmail(c *Context) {
	var body signInBody
	if err := c.ParseJSON(&body); err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeInvalidEmailOrPassword))
		return
	}

	email := strings.ToLower(strings.TrimSpace(body.Email))
	user, err := c.Auth.cfg.store.FindUserByEmail(c.R.Context(), email)
	if err != nil {
		if !errors.Is(err, berrors.ErrNotFound) {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
		if _, err := c.Auth.cfg.hasher.Hash(body.Password); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
		c.WriteError(apierror.WithCode(http.StatusUnauthorized, apierror.CodeInvalidEmailOrPassword))
		return
	}

	account, err := c.Auth.cfg.store.FindAccountByUserAndProvider(c.R.Context(), user.ID, constants.ProviderCredential)
	if err != nil || account.Password == "" {
		if err != nil && !errors.Is(err, berrors.ErrNotFound) {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
		if _, err := c.Auth.cfg.hasher.Hash(body.Password); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
		c.WriteError(apierror.WithCode(http.StatusUnauthorized, apierror.CodeInvalidEmailOrPassword))
		return
	}

	valid, err := c.Auth.cfg.hasher.Verify(account.Password, body.Password)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	if !valid {
		c.WriteError(apierror.WithCode(http.StatusUnauthorized, apierror.CodeInvalidEmailOrPassword))
		return
	}

	if c.Auth.cfg.emailPassword.requireEmailVerification && !user.EmailVerified {
		if c.Auth.cfg.emailVerification.sendOnSignIn && c.Auth.cfg.emailVerification.sendVerificationEmail != nil {
			if err := sendVerificationEmailToUser(c, user, body.CallbackURL); err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
				return
			}
		}
		c.WriteError(apierror.WithCode(http.StatusForbidden, apierror.CodeEmailNotVerified))
		return
	}

	rememberMe := true
	if body.RememberMe != nil {
		rememberMe = *body.RememberMe
	}

	sess, err := c.Auth.createSession(c, user.ID, rememberMe)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusUnauthorized, apierror.CodeFailedToCreateSession))
		return
	}

	if body.CallbackURL != "" {
		c.W.Header().Set("Location", body.CallbackURL)
	}

	c.WriteJSON(http.StatusOK, types.SignInResponse{
		Redirect: body.CallbackURL != "",
		Token:    sess.Token,
		URL:      body.CallbackURL,
		User:     toUserResponse(user),
	})
}

func handleSignOut(c *Context) {
	if token, ok := c.SessionToken(); ok {
		_ = c.Auth.cfg.store.DeleteSession(c.R.Context(), token)
	}
	cookieDelete(c)
	c.WriteJSON(http.StatusOK, types.SignOutResponse{Success: true})
}

func validateSignUpInput(c *Context, name, email, password string) *apierror.Error {
	if !crypto.ValidateEmail(email) {
		return apierror.WithCode(http.StatusBadRequest, apierror.CodeInvalidEmail)
	}
	if password == "" {
		return apierror.WithCode(http.StatusBadRequest, apierror.CodeInvalidPassword)
	}
	if len(password) < c.Auth.cfg.minPassword {
		return apierror.WithCode(http.StatusBadRequest, apierror.CodePasswordTooShort)
	}
	if len(password) > c.Auth.cfg.maxPassword {
		return apierror.WithCode(http.StatusBadRequest, apierror.CodePasswordTooLong)
	}
	if name == "" {
		return apierror.New(http.StatusBadRequest, apierror.CodeInvalidEmail, constants.MsgNameRequired)
	}
	if err := c.Auth.ValidatePasswords(password); err != nil {
		return apierror.New(http.StatusBadRequest, apierror.CodeInvalidPassword, err.Error())
	}
	return nil
}

func decodeRawBody(raw map[string]json.RawMessage, dst any) error {
	data, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}

func createUserWithCredential(c *Context, name string, email string, password string, image *string, additional map[string]any) (*types.User, *types.Account, error) {
	hash, err := c.Auth.cfg.hasher.Hash(password)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	userID, err := id.Generate(32)
	if err != nil {
		return nil, nil, err
	}
	user := &types.User{
		ID: userID, Name: name, Email: email, EmailVerified: false,
		Image: image, CreatedAt: now, UpdatedAt: now,
		Additional: applyDefaultAdditionalFields(additional, c.Auth.cfg.user.additionalFields),
	}
	if err := c.Auth.cfg.store.CreateUser(c.R.Context(), user); err != nil {
		return nil, nil, err
	}
	accountID, err := id.Generate(32)
	if err != nil {
		return nil, nil, err
	}
	account := &types.Account{
		ID: accountID, AccountID: userID, ProviderID: constants.ProviderCredential,
		UserID: userID, Password: hash, CreatedAt: now, UpdatedAt: now,
	}
	if err := c.Auth.cfg.store.CreateAccount(c.R.Context(), account); err != nil {
		return nil, nil, err
	}
	return user, account, nil
}

func cookieDelete(c *Context) {
	cookie.DeleteSessionCookies(c.W, c.Auth.cfg.cookie)
}
