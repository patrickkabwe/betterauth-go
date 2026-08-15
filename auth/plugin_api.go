package auth

import (
	"context"
	"encoding/json"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/internal/cookie"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

// ExtStore returns the plugin extension store when supported. It transparently
// unwraps store decorators (e.g. the database-hooks wrapper) so plugin storage
// keeps working when DatabaseHooks are configured.
func ExtStore(s store.Store) (store.ExtStore, bool) {
	if ext, ok := s.(store.ExtStore); ok {
		return ext, true
	}
	if u, ok := s.(interface{ Unwrap() store.Store }); ok {
		return ExtStore(u.Unwrap())
	}
	return nil, false
}

// NewSession creates a session and sets cookies (exported for plugins).
func (a *Auth) NewSession(c *Context, userID string, rememberMe bool) (*types.Session, error) {
	return a.createSession(c, userID, rememberMe)
}

// CanLinkAccountEmail reports whether account-linking policy permits the OAuth email.
func (a *Auth) CanLinkAccountEmail(existingEmail string, oauthEmail string) bool {
	return strings.EqualFold(existingEmail, oauthEmail) || a.cfg.account.allowDifferentEmails
}

// ApplyUserInfoOnLink applies configured user profile updates after account linking.
func (a *Auth) ApplyUserInfoOnLink(c *Context, userID string, info provider.OAuthUser) *types.User {
	return a.applyUserInfoOnLink(c, userID, info)
}

// VerifyPassword checks a password against a stored hash.
func (a *Auth) VerifyPassword(hash, password string) (bool, error) {
	return a.cfg.hasher.Verify(hash, password)
}

// HashPassword hashes a password with the configured hasher.
func (a *Auth) HashPassword(password string) (string, error) {
	return a.cfg.hasher.Hash(password)
}

// ValidatePasswords runs plugin password validators.
func (a *Auth) ValidatePasswords(password string) error {
	for _, fn := range a.cfg.passwordValidators {
		if err := fn(password); err != nil {
			return err
		}
	}
	return nil
}

// CreateVerification stores a verification token.
func (a *Auth) CreateVerification(ctx context.Context, identifier, value string, expires time.Duration) error {
	now := time.Now()
	vID, err := id.Generate(32)
	if err != nil {
		return err
	}
	return a.cfg.store.CreateVerification(ctx, &types.Verification{
		ID: vID, Identifier: identifier, Value: value,
		ExpiresAt: now.Add(expires), CreatedAt: now, UpdatedAt: now,
	})
}

// ConsumeVerification loads and deletes a verification by identifier.
func (a *Auth) ConsumeVerification(ctx context.Context, identifier string) (*types.Verification, error) {
	v, err := a.cfg.store.FindVerificationByIdentifier(ctx, identifier)
	if err != nil {
		return nil, err
	}
	if time.Now().After(v.ExpiresAt) {
		_ = a.cfg.store.DeleteVerificationByIdentifier(ctx, identifier)
		return nil, berrors.ErrNotFound
	}
	_ = a.cfg.store.DeleteVerificationByIdentifier(ctx, identifier)
	return v, nil
}

// FindUserByAdditional scans users for an additional field value (in-memory friendly).
func (a *Auth) FindUserByAdditional(ctx context.Context, key string, value any) (*types.User, error) {
	users, err := a.cfg.store.ListUsers(ctx, store.ListUsersOpts{Limit: 10000})
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.Additional != nil {
			if v, ok := u.Additional[key]; ok && v == value {
				cp := u
				return &cp, nil
			}
		}
	}
	return nil, berrors.ErrNotFound
}

// SetUserAdditional updates user additional fields.
func (a *Auth) SetUserAdditional(ctx context.Context, userID string, fields map[string]any) (*types.User, error) {
	return a.cfg.store.UpdateUser(ctx, userID, store.UserUpdate{Additional: fields})
}

// UserAdditional returns a value from user additional fields.
func UserAdditional(u *types.User, key string) (any, bool) {
	if u == nil || u.Additional == nil {
		return nil, false
	}
	v, ok := u.Additional[key]
	return v, ok
}

// UserAdditionalString returns a string additional field.
func UserAdditionalString(u *types.User, key string) string {
	v, ok := UserAdditional(u, key)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// UserAdditionalBool returns a bool additional field.
func UserAdditionalBool(u *types.User, key string) bool {
	v, ok := UserAdditional(u, key)
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

// SessionAdditional returns a session additional field.
func SessionAdditional(s *types.Session, key string) (any, bool) {
	if s == nil || s.Additional == nil {
		return nil, false
	}
	v, ok := s.Additional[key]
	return v, ok
}

// SetSessionAdditional updates session additional fields.
func (a *Auth) SetSessionAdditional(ctx context.Context, token string, fields map[string]any) (*types.Session, error) {
	return a.cfg.store.UpdateSession(ctx, token, store.SessionUpdate{Additional: fields, UpdatedAt: ptrTime(time.Now())})
}

// ClearSessionCookie removes session cookies.
func (a *Auth) ClearSessionCookie(c *Context) {
	cookie.DeleteSessionCookies(c.W, a.cfg.cookie)
}

// SignSessionToken signs a raw session token for bearer transport.
func (a *Auth) SignSessionToken(token string) string {
	return cookie.SignCookie(token, a.cfg.secret)
}

// VerifySignedSessionToken verifies a signed bearer token.
func (a *Auth) VerifySignedSessionToken(signed string) (string, bool) {
	return cookie.VerifySignedCookieAny(signed, a.cfg.secrets)
}

// VerificationPayload unmarshals JSON stored in verification value.
func VerificationPayload(v *types.Verification, dst any) error {
	return json.Unmarshal([]byte(v.Value), dst)
}

// MarshalVerificationPayload marshals data for verification storage.
func MarshalVerificationPayload(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// NormalizeEmail lowercases and trims email.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
