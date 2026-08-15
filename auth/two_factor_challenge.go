package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/cookie"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

const (
	twoFactorChallengeMaxAgeSeconds = 10 * 60
	twoFactorChallengeExpires       = 10 * time.Minute
)

// TwoFactorSignInMethodsPlugin reports which second factors are available for a user.
type TwoFactorSignInMethodsPlugin interface {
	Plugin
	TwoFactorSignInMethods(ctx context.Context, s store.Store, user *types.User) ([]string, error)
	TwoFactorTrustDeviceMaxAge() time.Duration
}

// TwoFactorChallenge carries either the current session or a pending sign-in challenge.
type TwoFactorChallenge struct {
	Session    *types.Session
	User       *types.User
	Identifier string
	RememberMe bool
	Pending    bool
}

type twoFactorChallengeValue struct {
	UserID     string `json:"userId"`
	RememberMe bool   `json:"rememberMe"`
}

// StartTwoFactorSignIn writes the Better Auth two-factor sign-in response when needed.
func (a *Auth) StartTwoFactorSignIn(c *Context, user *types.User, rememberMe bool) bool {
	if !UserAdditionalBool(user, constants.FieldTwoFactorEnabled) {
		return false
	}
	plugin, ok := a.twoFactorPlugin()
	if !ok {
		return false
	}
	trusted, ok := a.rotateTrustedDevice(c, user.ID, plugin.TwoFactorTrustDeviceMaxAge())
	if !ok {
		return true
	}
	if trusted {
		return false
	}
	methods, err := plugin.TwoFactorSignInMethods(c.R.Context(), a.cfg.store, user)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return true
	}
	identifier, err := a.createTwoFactorChallenge(c.R.Context(), user.ID, rememberMe)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return true
	}
	cookie.SetTwoFactorCookie(c.W, a.cfg.cookie, a.cfg.secret, identifier, twoFactorChallengeMaxAgeSeconds)
	c.WriteJSON(http.StatusOK, map[string]any{
		"twoFactorRedirect": true,
		"twoFactorMethods":  methods,
	})
	return true
}

// ResolveTwoFactorChallenge returns the active session or pending 2FA sign-in challenge.
func (a *Auth) ResolveTwoFactorChallenge(c *Context) (*TwoFactorChallenge, bool) {
	sess, user, err := c.GetSession()
	if err == nil {
		return &TwoFactorChallenge{Session: sess, User: user}, true
	}
	identifier, ok := cookie.GetTwoFactorCookieAny(c.R, a.cfg.cookie, a.cfg.secrets)
	if !ok {
		c.WriteError(apierror.New(http.StatusUnauthorized, "INVALID_TWO_FACTOR_COOKIE", "Invalid two-factor cookie"))
		return nil, false
	}
	v, err := a.cfg.store.FindVerificationByIdentifier(c.R.Context(), identifier)
	if err != nil || time.Now().After(v.ExpiresAt) {
		_ = a.cfg.store.DeleteVerificationByIdentifier(c.R.Context(), identifier)
		cookie.DeleteTwoFactorCookie(c.W, a.cfg.cookie)
		c.WriteError(apierror.New(http.StatusUnauthorized, "INVALID_TWO_FACTOR_COOKIE", "Invalid two-factor cookie"))
		return nil, false
	}
	value, err := parseTwoFactorChallengeValue(v.Value)
	if err != nil {
		_ = a.cfg.store.DeleteVerificationByIdentifier(c.R.Context(), identifier)
		cookie.DeleteTwoFactorCookie(c.W, a.cfg.cookie)
		c.WriteError(apierror.New(http.StatusUnauthorized, "INVALID_TWO_FACTOR_COOKIE", "Invalid two-factor cookie"))
		return nil, false
	}
	user, err = a.cfg.store.FindUserByID(c.R.Context(), value.UserID)
	if err != nil {
		_ = a.cfg.store.DeleteVerificationByIdentifier(c.R.Context(), identifier)
		cookie.DeleteTwoFactorCookie(c.W, a.cfg.cookie)
		c.WriteError(apierror.New(http.StatusUnauthorized, "INVALID_TWO_FACTOR_COOKIE", "Invalid two-factor cookie"))
		return nil, false
	}
	return &TwoFactorChallenge{
		User:       user,
		Identifier: identifier,
		RememberMe: value.RememberMe,
		Pending:    true,
	}, true
}

// CompleteTwoFactorChallenge consumes a pending challenge and issues a session.
func (a *Auth) CompleteTwoFactorChallenge(c *Context, challenge *TwoFactorChallenge, trustDevice bool, trustDeviceMaxAge time.Duration) (*types.Session, *types.User, bool) {
	if !challenge.Pending {
		return challenge.Session, challenge.User, true
	}
	v, err := a.ConsumeVerification(c.R.Context(), challenge.Identifier)
	if err != nil {
		cookie.DeleteTwoFactorCookie(c.W, a.cfg.cookie)
		c.WriteError(apierror.New(http.StatusUnauthorized, "INVALID_TWO_FACTOR_COOKIE", "Invalid two-factor cookie"))
		return nil, nil, false
	}
	value, err := parseTwoFactorChallengeValue(v.Value)
	if err != nil || value.UserID != challenge.User.ID {
		cookie.DeleteTwoFactorCookie(c.W, a.cfg.cookie)
		c.WriteError(apierror.New(http.StatusUnauthorized, "INVALID_TWO_FACTOR_COOKIE", "Invalid two-factor cookie"))
		return nil, nil, false
	}
	_ = a.cfg.store.DeleteVerificationByIdentifier(c.R.Context(), "2fa-attempts-"+challenge.Identifier)
	sess, err := a.createSession(c, challenge.User.ID, value.RememberMe)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeFailedToCreateSession))
		return nil, nil, false
	}
	if trustDevice {
		if err := a.setTrustedDevice(c, challenge.User.ID, trustDeviceMaxAge); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return nil, nil, false
		}
	}
	cookie.DeleteTwoFactorCookie(c.W, a.cfg.cookie)
	return sess, challenge.User, true
}

// ClearTrustedDevice removes the trusted-device cookie and its server-side record.
func (a *Auth) ClearTrustedDevice(c *Context) {
	value, ok := cookie.GetTrustDeviceCookieAny(c.R, a.cfg.cookie, a.cfg.secrets)
	if ok {
		_, identifier, valid := splitTrustedDeviceValue(value)
		if valid {
			_ = a.cfg.store.DeleteVerificationByIdentifier(c.R.Context(), identifier)
		}
	}
	cookie.DeleteTrustDeviceCookie(c.W, a.cfg.cookie)
}

func (a *Auth) twoFactorPlugin() (TwoFactorSignInMethodsPlugin, bool) {
	for _, plugin := range a.cfg.plugins {
		if plugin.ID() != constants.PluginTwoFactor {
			continue
		}
		twoFactorPlugin, ok := plugin.(TwoFactorSignInMethodsPlugin)
		return twoFactorPlugin, ok
	}
	return nil, false
}

func (a *Auth) createTwoFactorChallenge(ctx context.Context, userID string, rememberMe bool) (string, error) {
	token, err := id.Generate(20)
	if err != nil {
		return "", err
	}
	identifier := "2fa-" + token
	value, err := json.Marshal(twoFactorChallengeValue{UserID: userID, RememberMe: rememberMe})
	if err != nil {
		return "", err
	}
	if err := a.CreateVerification(ctx, identifier, string(value), twoFactorChallengeExpires); err != nil {
		return "", err
	}
	if err := a.CreateVerification(ctx, "2fa-attempts-"+identifier, "0", twoFactorChallengeExpires); err != nil {
		return "", err
	}
	return identifier, nil
}

func (a *Auth) rotateTrustedDevice(c *Context, userID string, maxAge time.Duration) (bool, bool) {
	value, ok := cookie.GetTrustDeviceCookieAny(c.R, a.cfg.cookie, a.cfg.secrets)
	if !ok {
		return false, true
	}
	token, identifier, valid := splitTrustedDeviceValue(value)
	if !valid || !trustedDeviceTokenValid(a.cfg.secret, userID, identifier, token) {
		cookie.DeleteTrustDeviceCookie(c.W, a.cfg.cookie)
		return false, true
	}
	v, err := a.cfg.store.FindVerificationByIdentifier(c.R.Context(), identifier)
	if err != nil || v.Value != userID || time.Now().After(v.ExpiresAt) {
		_ = a.cfg.store.DeleteVerificationByIdentifier(c.R.Context(), identifier)
		cookie.DeleteTrustDeviceCookie(c.W, a.cfg.cookie)
		return false, true
	}
	_ = a.cfg.store.DeleteVerificationByIdentifier(c.R.Context(), identifier)
	if err := a.setTrustedDevice(c, userID, maxAge); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false, false
	}
	return true, true
}

func (a *Auth) setTrustedDevice(c *Context, userID string, maxAge time.Duration) error {
	if maxAge <= 0 {
		maxAge = 30 * 24 * time.Hour
	}
	rawID, err := id.Generate(32)
	if err != nil {
		return err
	}
	identifier := "trust-device-" + rawID
	if err := a.CreateVerification(c.R.Context(), identifier, userID, maxAge); err != nil {
		return err
	}
	token := trustedDeviceToken(a.cfg.secret, userID, identifier)
	cookie.SetTrustDeviceCookie(c.W, a.cfg.cookie, a.cfg.secret, token+"!"+identifier, int(maxAge.Seconds()))
	return nil
}

func splitTrustedDeviceValue(value string) (string, string, bool) {
	parts := strings.Split(value, "!")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func trustedDeviceTokenValid(secret string, userID string, identifier string, token string) bool {
	expected := trustedDeviceToken(secret, userID, identifier)
	return hmac.Equal([]byte(token), []byte(expected))
}

func trustedDeviceToken(secret string, userID string, identifier string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(userID + "!" + identifier))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func parseTwoFactorChallengeValue(value string) (twoFactorChallengeValue, error) {
	var parsed twoFactorChallengeValue
	if err := json.Unmarshal([]byte(value), &parsed); err != nil {
		return twoFactorChallengeValue{}, err
	}
	if parsed.UserID == "" {
		return twoFactorChallengeValue{}, apierror.New(http.StatusUnauthorized, "INVALID_TWO_FACTOR_COOKIE", "Invalid two-factor cookie")
	}
	return parsed, nil
}
