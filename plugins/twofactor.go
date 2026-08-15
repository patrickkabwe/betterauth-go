package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TwoFactorOptions configures two-factor authentication.
type TwoFactorOptions struct {
	Issuer                   string
	SendOTP                  func(ctx context.Context, user *types.User, otp string) error
	OTPExpiresIn             time.Duration
	OTPLength                int
	OTPAllowedAttempts       int
	AllowPasswordless        bool
	TrustDeviceMaxAge        time.Duration
	AccountLockout           *TwoFactorAccountLockoutOptions
	TOTPDigits               int
	TOTPPeriod               time.Duration
	SkipVerificationOnEnable bool
}

// TwoFactorAccountLockoutOptions configures account-level 2FA failure lockout.
type TwoFactorAccountLockoutOptions struct {
	Enabled           *bool
	MaxFailedAttempts int
	Duration          time.Duration
}

type twoFactorAccountLockout struct {
	enabled           bool
	maxFailedAttempts int
	duration          time.Duration
}

// TwoFactor adds TOTP, OTP, and backup code 2FA.
func TwoFactor(opts TwoFactorOptions) auth.Plugin {
	issuer := opts.Issuer
	if issuer == "" {
		issuer = "Better Auth"
	}
	otpExpires := opts.OTPExpiresIn
	if otpExpires == 0 {
		otpExpires = 3 * time.Minute
	}
	otpLength := opts.OTPLength
	if otpLength == 0 {
		otpLength = 6
	}
	allowedAttempts := opts.OTPAllowedAttempts
	if allowedAttempts == 0 {
		allowedAttempts = 5
	}
	trustDeviceMaxAge := opts.TrustDeviceMaxAge
	if trustDeviceMaxAge == 0 {
		trustDeviceMaxAge = 30 * 24 * time.Hour
	}
	totpDigits := resolveTOTPDigits(opts.TOTPDigits)
	totpPeriod := opts.TOTPPeriod
	if totpPeriod == 0 {
		totpPeriod = 30 * time.Second
	}
	lockout := resolveTwoFactorAccountLockout(opts.AccountLockout)
	return twoFactorPlugin{
		basePlugin: basePlugin{
			id: constants.PluginTwoFactor,
			routes: []auth.PluginRoute{
				rt(http.MethodPost, "/two-factor/enable", func(c *auth.Context) {
					sess, user, ok := c.RequireSession()
					if !ok {
						return
					}
					body, ok := parseTwoFactorManagementBody(c)
					if !ok {
						return
					}
					if !requireTwoFactorPassword(c, user, body.Password, opts.AllowPasswordless) {
						return
					}
					ext, ok := auth.ExtStore(c.Auth.Store())
					if !ok {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
						return
					}
					effectiveIssuer := issuer
					if body.Issuer != "" {
						effectiveIssuer = body.Issuer
					}
					key, err := totp.Generate(totp.GenerateOpts{
						Issuer: effectiveIssuer, AccountName: user.Email,
						Digits: totpDigits, Period: uint(totpPeriod.Seconds()),
					})
					if err != nil {
						c.WriteError(apierror.New(http.StatusInternalServerError, constants.CodeInternalServerError, constants.MsgFailedToGenerateTOTP))
						return
					}
					recID, err := id.Generate(32)
					if err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
					backupCodes, encodedBackupCodes, err := generateTwoFactorBackupCodes()
					if err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
					verified := opts.SkipVerificationOnEnable
					existing, err := ext.FindTwoFactorByUserID(c.R.Context(), user.ID)
					if err != nil && !errors.Is(err, berrors.ErrNotFound) {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
					if existing != nil && existing.Verified {
						verified = true
					}
					now := time.Now()
					if err := ext.CreateTwoFactor(c.R.Context(), &types.TwoFactorRecord{
						ID: recID, UserID: user.ID, Secret: key.Secret(),
						BackupCodes: encodedBackupCodes, Verified: verified, CreatedAt: now, UpdatedAt: now,
					}); err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
					if opts.SkipVerificationOnEnable && !auth.UserAdditionalBool(user, constants.FieldTwoFactorEnabled) {
						updated, err := c.Auth.SetUserAdditional(c.R.Context(), user.ID, map[string]any{constants.FieldTwoFactorEnabled: true})
						if err != nil {
							c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
							return
						}
						c.Auth.SyncUserSession(c, sess, updated)
					}
					c.WriteJSON(http.StatusOK, map[string]any{"totpURI": key.URL(), "backupCodes": backupCodes})
				}),
				rt(http.MethodPost, "/two-factor/disable", func(c *auth.Context) {
					sess, user, ok := c.RequireSession()
					if !ok {
						return
					}
					body, ok := parseTwoFactorManagementBody(c)
					if !ok {
						return
					}
					if !requireTwoFactorPassword(c, user, body.Password, opts.AllowPasswordless) {
						return
					}
					ext, ok := auth.ExtStore(c.Auth.Store())
					if !ok {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
						return
					}
					if err := ext.DeleteTwoFactor(c.R.Context(), user.ID); err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
					updated, err := c.Auth.SetUserAdditional(c.R.Context(), user.ID, map[string]any{constants.FieldTwoFactorEnabled: false})
					if err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
					c.Auth.SyncUserSession(c, sess, updated)
					c.Auth.ClearTrustedDevice(c)
					c.WriteJSON(http.StatusOK, map[string]bool{"status": true})
				}),
				rt(http.MethodPost, "/two-factor/get-totp-uri", func(c *auth.Context) {
					_, user, ok := c.RequireSession()
					if !ok {
						return
					}
					body, ok := parseTwoFactorManagementBody(c)
					if !ok {
						return
					}
					if !requireTwoFactorPassword(c, user, body.Password, opts.AllowPasswordless) {
						return
					}
					ext, ok := auth.ExtStore(c.Auth.Store())
					if !ok {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
						return
					}
					rec, err := ext.FindTwoFactorByUserID(c.R.Context(), user.ID)
					if err != nil {
						c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeTwoFactorNotEnabled))
						return
					}
					key, err := totp.Generate(totp.GenerateOpts{
						Issuer: issuer, AccountName: user.Email, Secret: []byte(rec.Secret),
						Digits: totpDigits, Period: uint(totpPeriod.Seconds()),
					})
					if err != nil {
						c.WriteError(apierror.New(http.StatusInternalServerError, constants.CodeInternalServerError, constants.MsgFailedToGenerateTOTP))
						return
					}
					c.WriteJSON(http.StatusOK, map[string]string{"totpURI": key.URL()})
				}),
				rt(http.MethodPost, "/two-factor/verify-totp", func(c *auth.Context) {
					challenge, ok := c.Auth.ResolveTwoFactorChallenge(c)
					if !ok {
						return
					}
					user := challenge.User
					var body struct {
						Code        string `json:"code"`
						TrustDevice bool   `json:"trustDevice"`
					}
					if err := c.ParseJSON(&body); err != nil {
						c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCode))
						return
					}
					ext, ok := auth.ExtStore(c.Auth.Store())
					if !ok {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
						return
					}
					rec, err := ext.FindTwoFactorByUserID(c.R.Context(), user.ID)
					if err != nil || (challenge.Pending && !rec.Verified) {
						c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCode))
						return
					}
					if challenge.Pending && !assertTwoFactorNotLocked(c, ext, rec, lockout) {
						return
					}
					if challenge.Pending && !assertTwoFactorChallengeAttemptAvailable(c, challenge, allowedAttempts) {
						return
					}
					totpValid, err := totp.ValidateCustom(body.Code, rec.Secret, time.Now(), totp.ValidateOpts{
						Digits: totpDigits, Period: uint(totpPeriod.Seconds()),
					})
					if err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
					if !totpValid {
						if challenge.Pending && !recordTwoFactorChallengeAttempt(c, challenge) {
							return
						}
						if challenge.Pending && !recordTwoFactorFailure(c, ext, rec, lockout) {
							return
						}
						c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCode))
						return
					}
					if challenge.Pending && !resetTwoFactorFailures(c, ext, rec, lockout) {
						return
					}
					updated := user
					if !rec.Verified {
						if err := ext.UpdateTwoFactor(c.R.Context(), user.ID, rec.Secret, rec.BackupCodes, true); err != nil {
							c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
							return
						}
					}
					if !auth.UserAdditionalBool(user, constants.FieldTwoFactorEnabled) {
						updated, err = c.Auth.SetUserAdditional(c.R.Context(), user.ID, map[string]any{constants.FieldTwoFactorEnabled: true})
						if err != nil {
							c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
							return
						}
					}
					sess, user, ok := c.Auth.CompleteTwoFactorChallenge(c, challenge, body.TrustDevice, trustDeviceMaxAge)
					if !ok {
						return
					}
					if !challenge.Pending {
						c.Auth.SyncUserSession(c, sess, updated)
						user = updated
					}
					c.WriteJSON(http.StatusOK, map[string]any{"token": sess.Token, "user": user})
				}),
				rt(http.MethodPost, "/two-factor/send-otp", func(c *auth.Context) {
					if opts.SendOTP == nil {
						c.WriteError(apierror.New(http.StatusBadRequest, "OTP_NOT_CONFIGURED", "otp isn't configured"))
						return
					}
					challenge, ok := c.Auth.ResolveTwoFactorChallenge(c)
					if !ok {
						return
					}
					otp, err := numericOTP(otpLength)
					if err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
					if err := c.Auth.CreateVerification(c.R.Context(), twoFactorOTPIdentifier(twoFactorChallengeKey(challenge)), otp+":0", otpExpires); err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
					if err := opts.SendOTP(c.R.Context(), challenge.User, otp); err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
					c.WriteJSON(http.StatusOK, map[string]bool{"status": true})
				}),
				rt(http.MethodPost, "/two-factor/verify-otp", func(c *auth.Context) {
					challenge, ok := c.Auth.ResolveTwoFactorChallenge(c)
					if !ok {
						return
					}
					user := challenge.User
					var body struct {
						Code        string `json:"code"`
						TrustDevice bool   `json:"trustDevice"`
					}
					if err := c.ParseJSON(&body); err != nil || body.Code == "" {
						c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCode))
						return
					}
					ext, extOK := auth.ExtStore(c.Auth.Store())
					var rec *types.TwoFactorRecord
					if extOK {
						rec, _ = ext.FindTwoFactorByUserID(c.R.Context(), user.ID)
					}
					if challenge.Pending && rec == nil {
						c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeTwoFactorNotEnabled))
						return
					}
					if challenge.Pending && rec != nil && !assertTwoFactorNotLocked(c, ext, rec, lockout) {
						return
					}
					consumeResult := consumeTwoFactorOTP(c, twoFactorChallengeKey(challenge), body.Code, allowedAttempts)
					if consumeResult == twoFactorOTPConsumeFailed {
						return
					}
					if consumeResult == twoFactorOTPConsumeInvalid {
						if challenge.Pending && rec != nil && !recordTwoFactorFailure(c, ext, rec, lockout) {
							return
						}
						c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCode))
						return
					}
					if challenge.Pending && rec != nil && !resetTwoFactorFailures(c, ext, rec, lockout) {
						return
					}
					if rec != nil && !rec.Verified {
						ext, ok := auth.ExtStore(c.Auth.Store())
						if !ok {
							c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
							return
						}
						if err := ext.UpdateTwoFactor(c.R.Context(), user.ID, rec.Secret, rec.BackupCodes, true); err != nil {
							c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
							return
						}
					}
					updated := user
					if !auth.UserAdditionalBool(user, constants.FieldTwoFactorEnabled) {
						var err error
						updated, err = c.Auth.SetUserAdditional(c.R.Context(), user.ID, map[string]any{constants.FieldTwoFactorEnabled: true})
						if err != nil {
							c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
							return
						}
					}
					sess, user, ok := c.Auth.CompleteTwoFactorChallenge(c, challenge, body.TrustDevice, trustDeviceMaxAge)
					if !ok {
						return
					}
					if !challenge.Pending {
						c.Auth.SyncUserSession(c, sess, updated)
						user = updated
					}
					c.WriteJSON(http.StatusOK, map[string]any{"token": sess.Token, "user": user})
				}),
				rt(http.MethodPost, "/two-factor/verify-backup-code", func(c *auth.Context) {
					challenge, ok := c.Auth.ResolveTwoFactorChallenge(c)
					if !ok {
						return
					}
					user := challenge.User
					var body struct {
						Code        string `json:"code"`
						TrustDevice bool   `json:"trustDevice"`
					}
					if err := c.ParseJSON(&body); err != nil {
						c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCode))
						return
					}
					ext, ok := auth.ExtStore(c.Auth.Store())
					if !ok {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
						return
					}
					rec, err := ext.FindTwoFactorByUserID(c.R.Context(), user.ID)
					if err != nil {
						c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCode))
						return
					}
					if challenge.Pending && !assertTwoFactorNotLocked(c, ext, rec, lockout) {
						return
					}
					if challenge.Pending && !assertTwoFactorChallengeAttemptAvailable(c, challenge, allowedAttempts) {
						return
					}
					var codes []string
					_ = json.Unmarshal([]byte(rec.BackupCodes), &codes)
					found := false
					remaining := make([]string, 0, len(codes))
					for _, code := range codes {
						if !found && code == body.Code {
							found = true
							continue
						}
						remaining = append(remaining, code)
					}
					if !found {
						if challenge.Pending && !recordTwoFactorChallengeAttempt(c, challenge) {
							return
						}
						if challenge.Pending && !recordTwoFactorFailure(c, ext, rec, lockout) {
							return
						}
						c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCode))
						return
					}
					if challenge.Pending && !resetTwoFactorFailures(c, ext, rec, lockout) {
						return
					}
					b, err := json.Marshal(remaining)
					if err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
					if err := ext.UpdateTwoFactor(c.R.Context(), user.ID, rec.Secret, string(b), rec.Verified); err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
					sess, user, ok := c.Auth.CompleteTwoFactorChallenge(c, challenge, body.TrustDevice, trustDeviceMaxAge)
					if !ok {
						return
					}
					c.WriteJSON(http.StatusOK, map[string]any{"token": sess.Token, "user": user})
				}),
				rt(http.MethodPost, "/two-factor/generate-backup-codes", func(c *auth.Context) {
					_, user, ok := c.RequireSession()
					if !ok {
						return
					}
					body, ok := parseTwoFactorManagementBody(c)
					if !ok {
						return
					}
					if !auth.UserAdditionalBool(user, constants.FieldTwoFactorEnabled) {
						c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeTwoFactorNotEnabled))
						return
					}
					if !requireTwoFactorPassword(c, user, body.Password, opts.AllowPasswordless) {
						return
					}
					ext, ok := auth.ExtStore(c.Auth.Store())
					if !ok {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
						return
					}
					rec, err := ext.FindTwoFactorByUserID(c.R.Context(), user.ID)
					if err != nil {
						c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeTwoFactorNotEnabled))
						return
					}
					codes, encodedCodes, err := generateTwoFactorBackupCodes()
					if err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
					if err := ext.UpdateTwoFactor(c.R.Context(), user.ID, rec.Secret, encodedCodes, rec.Verified); err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
					c.WriteJSON(http.StatusOK, map[string]any{"status": true, "backupCodes": codes})
				}),
			},
		},
		sendOTP:           opts.SendOTP != nil,
		trustDeviceMaxAge: trustDeviceMaxAge,
	}
}

type twoFactorPlugin struct {
	basePlugin
	sendOTP           bool
	trustDeviceMaxAge time.Duration
}

func (p twoFactorPlugin) TwoFactorSignInMethods(ctx context.Context, s store.Store, user *types.User) ([]string, error) {
	methods := make([]string, 0, 2)
	if ext, ok := auth.ExtStore(s); ok {
		rec, err := ext.FindTwoFactorByUserID(ctx, user.ID)
		if err == nil && rec.Verified {
			methods = append(methods, "totp")
		}
	}
	if p.sendOTP {
		methods = append(methods, "otp")
	}
	return methods, nil
}

func (p twoFactorPlugin) TwoFactorTrustDeviceMaxAge() time.Duration {
	return p.trustDeviceMaxAge
}

func twoFactorOTPIdentifier(key string) string {
	return "2fa-otp-" + key
}

func twoFactorChallengeKey(challenge *auth.TwoFactorChallenge) string {
	if challenge.Pending {
		return challenge.Identifier
	}
	return challenge.User.ID + "!" + challenge.Session.ID
}

type twoFactorManagementBody struct {
	Password string `json:"password"`
	Issuer   string `json:"issuer"`
}

func parseTwoFactorManagementBody(c *auth.Context) (twoFactorManagementBody, bool) {
	var body twoFactorManagementBody
	if err := c.ParseJSON(&body); err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidPassword))
		return twoFactorManagementBody{}, false
	}
	return body, true
}

func requireTwoFactorPassword(c *auth.Context, user *types.User, password string, allowPasswordless bool) bool {
	required, ok := twoFactorPasswordRequired(c, user.ID, allowPasswordless)
	if !ok {
		return false
	}
	if !required {
		return true
	}
	if password == "" {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidPassword))
		return false
	}
	account, err := c.Auth.Store().FindAccountByUserAndProvider(c.R.Context(), user.ID, constants.ProviderCredential)
	if err != nil || account.Password == "" {
		_, _ = c.Auth.HashPassword(password)
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidPassword))
		return false
	}
	valid, err := c.Auth.VerifyPassword(account.Password, password)
	if err != nil || !valid {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidPassword))
		return false
	}
	return true
}

func twoFactorPasswordRequired(c *auth.Context, userID string, allowPasswordless bool) (bool, bool) {
	if !allowPasswordless {
		return true, true
	}
	account, err := c.Auth.Store().FindAccountByUserAndProvider(c.R.Context(), userID, constants.ProviderCredential)
	if err != nil {
		if errors.Is(err, berrors.ErrNotFound) {
			return false, true
		}
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false, false
	}
	return account.Password != "", true
}

func resolveTOTPDigits(value int) otp.Digits {
	if value == 8 {
		return otp.DigitsEight
	}
	return otp.DigitsSix
}

func resolveTwoFactorAccountLockout(opts *TwoFactorAccountLockoutOptions) twoFactorAccountLockout {
	enabled := true
	maxFailedAttempts := 10
	duration := 15 * time.Minute
	if opts != nil {
		if opts.Enabled != nil {
			enabled = *opts.Enabled
		}
		if opts.MaxFailedAttempts > 0 {
			maxFailedAttempts = opts.MaxFailedAttempts
		}
		if opts.Duration > 0 {
			duration = opts.Duration
		}
	}
	return twoFactorAccountLockout{
		enabled:           enabled,
		maxFailedAttempts: maxFailedAttempts,
		duration:          duration,
	}
}

func assertTwoFactorNotLocked(c *auth.Context, ext store.ExtStore, rec *types.TwoFactorRecord, lockout twoFactorAccountLockout) bool {
	if !lockout.enabled || rec.LockedUntil == nil {
		return true
	}
	if rec.LockedUntil.After(time.Now()) {
		c.WriteError(apierror.New(http.StatusTooManyRequests, "ACCOUNT_TEMPORARILY_LOCKED", "Too many failed verification attempts. Your account is temporarily locked. Please try again later."))
		return false
	}
	if err := ext.UpdateTwoFactorLockout(c.R.Context(), rec.UserID, 0, nil); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	rec.FailedVerificationCount = 0
	rec.LockedUntil = nil
	return true
}

func recordTwoFactorFailure(c *auth.Context, ext store.ExtStore, rec *types.TwoFactorRecord, lockout twoFactorAccountLockout) bool {
	if !lockout.enabled {
		return true
	}
	count := rec.FailedVerificationCount + 1
	var lockedUntil *time.Time
	if count >= lockout.maxFailedAttempts {
		lockExpires := time.Now().Add(lockout.duration)
		lockedUntil = &lockExpires
	}
	if err := ext.UpdateTwoFactorLockout(c.R.Context(), rec.UserID, count, lockedUntil); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	rec.FailedVerificationCount = count
	rec.LockedUntil = lockedUntil
	return true
}

func resetTwoFactorFailures(c *auth.Context, ext store.ExtStore, rec *types.TwoFactorRecord, lockout twoFactorAccountLockout) bool {
	if !lockout.enabled {
		return true
	}
	if err := ext.UpdateTwoFactorLockout(c.R.Context(), rec.UserID, 0, nil); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	rec.FailedVerificationCount = 0
	rec.LockedUntil = nil
	return true
}

func twoFactorChallengeAttemptsIdentifier(challenge *auth.TwoFactorChallenge) string {
	return "2fa-attempts-" + challenge.Identifier
}

func assertTwoFactorChallengeAttemptAvailable(c *auth.Context, challenge *auth.TwoFactorChallenge, allowedAttempts int) bool {
	if !challenge.Pending {
		return true
	}
	identifier := twoFactorChallengeAttemptsIdentifier(challenge)
	v, err := c.Auth.Store().FindVerificationByIdentifier(c.R.Context(), identifier)
	if err != nil {
		cancelTwoFactorChallenge(c, challenge)
		c.WriteError(apierror.New(http.StatusUnauthorized, "INVALID_TWO_FACTOR_COOKIE", "Invalid two-factor cookie"))
		return false
	}
	if time.Now().After(v.ExpiresAt) {
		cancelTwoFactorChallenge(c, challenge)
		c.WriteError(apierror.New(http.StatusUnauthorized, "INVALID_TWO_FACTOR_COOKIE", "Invalid two-factor cookie"))
		return false
	}
	attempts, err := strconv.Atoi(v.Value)
	if err != nil || attempts < 0 {
		attempts = allowedAttempts
	}
	if attempts >= allowedAttempts {
		cancelTwoFactorChallenge(c, challenge)
		c.WriteError(apierror.New(http.StatusBadRequest, "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE", "Too many attempts request a new code"))
		return false
	}
	return true
}

func recordTwoFactorChallengeAttempt(c *auth.Context, challenge *auth.TwoFactorChallenge) bool {
	if !challenge.Pending {
		return true
	}
	identifier := twoFactorChallengeAttemptsIdentifier(challenge)
	v, err := c.Auth.Store().FindVerificationByIdentifier(c.R.Context(), identifier)
	if err != nil {
		cancelTwoFactorChallenge(c, challenge)
		c.WriteError(apierror.New(http.StatusUnauthorized, "INVALID_TWO_FACTOR_COOKIE", "Invalid two-factor cookie"))
		return false
	}
	attempts, err := strconv.Atoi(v.Value)
	if err != nil || attempts < 0 {
		attempts = 0
	}
	now := time.Now()
	if err := c.Auth.Store().CreateVerification(c.R.Context(), &types.Verification{
		ID: v.ID, Identifier: v.Identifier, Value: strconv.Itoa(attempts + 1),
		ExpiresAt: v.ExpiresAt, CreatedAt: v.CreatedAt, UpdatedAt: now,
	}); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	return true
}

func cancelTwoFactorChallenge(c *auth.Context, challenge *auth.TwoFactorChallenge) {
	_ = c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), challenge.Identifier)
	_ = c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), twoFactorChallengeAttemptsIdentifier(challenge))
}

func generateTwoFactorBackupCodes() ([]string, string, error) {
	codes := make([]string, 10)
	for i := range codes {
		raw, err := id.Generate(10)
		if err != nil {
			return nil, "", err
		}
		codes[i] = raw[:5] + "-" + raw[5:]
	}
	encoded, err := json.Marshal(codes)
	if err != nil {
		return nil, "", err
	}
	return codes, string(encoded), nil
}

type twoFactorOTPConsumeResult string

const (
	twoFactorOTPConsumeSuccess twoFactorOTPConsumeResult = "success"
	twoFactorOTPConsumeInvalid twoFactorOTPConsumeResult = "invalid"
	twoFactorOTPConsumeFailed  twoFactorOTPConsumeResult = "failed"
)

func consumeTwoFactorOTP(c *auth.Context, key string, code string, allowedAttempts int) twoFactorOTPConsumeResult {
	identifier := twoFactorOTPIdentifier(key)
	v, err := c.Auth.Store().FindVerificationByIdentifier(c.R.Context(), identifier)
	if err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, "OTP_HAS_EXPIRED", "OTP has expired"))
		return twoFactorOTPConsumeFailed
	}
	if time.Now().After(v.ExpiresAt) {
		if err := c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), identifier); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return twoFactorOTPConsumeFailed
		}
		c.WriteError(apierror.New(http.StatusBadRequest, "OTP_HAS_EXPIRED", "OTP has expired"))
		return twoFactorOTPConsumeFailed
	}
	otp, attempts := splitTwoFactorOTPValue(v.Value)
	if attempts >= allowedAttempts {
		if err := c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), identifier); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return twoFactorOTPConsumeFailed
		}
		c.WriteError(apierror.New(http.StatusBadRequest, "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE", "Too many attempts request a new code"))
		return twoFactorOTPConsumeFailed
	}
	if otp != code {
		if err := saveTwoFactorOTPAttempts(c, v, attempts+1); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return twoFactorOTPConsumeFailed
		}
		return twoFactorOTPConsumeInvalid
	}
	if err := c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), identifier); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return twoFactorOTPConsumeFailed
	}
	return twoFactorOTPConsumeSuccess
}

func splitTwoFactorOTPValue(value string) (string, int) {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) == 1 {
		return parts[0], 0
	}
	attempts, err := strconv.Atoi(parts[1])
	if err != nil {
		return parts[0], 0
	}
	return parts[0], attempts
}

func saveTwoFactorOTPAttempts(c *auth.Context, v *types.Verification, attempts int) error {
	otp, _ := splitTwoFactorOTPValue(v.Value)
	now := time.Now()
	return c.Auth.Store().CreateVerification(c.R.Context(), &types.Verification{
		ID: v.ID, Identifier: v.Identifier, Value: otp + ":" + strconv.Itoa(attempts),
		ExpiresAt: v.ExpiresAt, CreatedAt: v.CreatedAt, UpdatedAt: now,
	})
}
