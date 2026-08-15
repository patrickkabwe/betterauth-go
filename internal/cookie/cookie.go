package cookie

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config holds cookie naming and attribute settings.
type Config struct {
	Prefix      string
	Secure      bool
	SameSite    http.SameSite
	Path        string
	Domain      string
	Partitioned bool
	// NameOverrides maps a logical cookie key ("session_token",
	// "dont_remember", "session_data") to a fully custom cookie name. When set,
	// the prefix and __Secure- prefix are not applied to that cookie.
	NameOverrides map[string]string
}

// resolveName returns a custom override name when configured, otherwise the
// computed prefix-based name (with __Secure- when Secure is set).
func (c Config) resolveName(key, computed string) string {
	if c.NameOverrides != nil {
		if override, ok := c.NameOverrides[key]; ok && override != "" {
			return override
		}
	}
	return computed
}

// DefaultConfig returns Better Auth compatible cookie defaults.
func DefaultConfig() Config {
	return Config{
		Prefix:   "better-auth",
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	}
}

// SessionTokenName returns the session cookie name (e.g. better-auth.session_token).
func (c Config) SessionTokenName() string {
	prefix := c.Prefix
	if prefix == "" {
		prefix = "better-auth"
	}
	name := prefix + ".session_token"
	if c.Secure {
		name = "__Secure-" + name
	}
	return c.resolveName("session_token", name)
}

// DontRememberName returns the dont_remember cookie name.
func (c Config) DontRememberName() string {
	prefix := c.Prefix
	if prefix == "" {
		prefix = "better-auth"
	}
	name := prefix + ".dont_remember"
	if c.Secure {
		name = "__Secure-" + name
	}
	return c.resolveName("dont_remember", name)
}

// TwoFactorName returns the two-factor challenge cookie name.
func (c Config) TwoFactorName() string {
	prefix := c.Prefix
	if prefix == "" {
		prefix = "better-auth"
	}
	name := prefix + ".two_factor"
	if c.Secure {
		name = "__Secure-" + name
	}
	return c.resolveName("two_factor", name)
}

// TrustDeviceName returns the trusted-device cookie name.
func (c Config) TrustDeviceName() string {
	prefix := c.Prefix
	if prefix == "" {
		prefix = "better-auth"
	}
	name := prefix + ".trust_device"
	if c.Secure {
		name = "__Secure-" + name
	}
	return c.resolveName("trust_device", name)
}

// SignCookie signs a value using HMAC-SHA256 with standard base64 encoding,
// matching better-call's serializeSignedCookie format: value.signature
func SignCookie(value, secret string) string {
	sig := signHMAC(value, secret)
	return value + "." + sig
}

// VerifySignedCookieAny verifies a signed cookie against any of the provided
// secrets (primary first, then rotated/old secrets) and returns the unsigned
// value on the first match.
func VerifySignedCookieAny(signed string, secrets []string) (string, bool) {
	for _, secret := range secrets {
		if value, ok := VerifySignedCookie(signed, secret); ok {
			return value, true
		}
	}
	return "", false
}

// VerifySignedCookie verifies and returns the unsigned cookie value.
func VerifySignedCookie(signed, secret string) (string, bool) {
	// Decode URI-encoded cookie values (better-call uses encodeURIComponent).
	// Use PathUnescape to avoid converting '+' to space (unlike QueryUnescape).
	if strings.Contains(signed, "%") {
		if decoded, err := url.PathUnescape(signed); err == nil {
			signed = decoded
		}
	}

	lastDot := strings.LastIndex(signed, ".")
	if lastDot <= 0 {
		return "", false
	}

	value := signed[:lastDot]
	sig := signed[lastDot+1:]

	expected := signHMAC(value, secret)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", false
	}
	return value, true
}

func signHMAC(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// SetSessionCookie sets the signed session token cookie on the response.
func SetSessionCookie(w http.ResponseWriter, cfg Config, secret, token string, maxAge int, dontRemember bool) {
	signed := SignCookie(token, secret)
	http.SetCookie(w, &http.Cookie{
		Name:        cfg.SessionTokenName(),
		Value:       signed,
		Path:        cfg.Path,
		Domain:      cfg.Domain,
		MaxAge:      maxAge,
		HttpOnly:    true,
		Secure:      cfg.Secure,
		SameSite:    cfg.SameSite,
		Partitioned: cfg.Partitioned,
	})

	if dontRemember {
		dontRememberSigned := SignCookie("true", secret)
		http.SetCookie(w, &http.Cookie{
			Name:        cfg.DontRememberName(),
			Value:       dontRememberSigned,
			Path:        cfg.Path,
			Domain:      cfg.Domain,
			HttpOnly:    true,
			Secure:      cfg.Secure,
			SameSite:    cfg.SameSite,
			Partitioned: cfg.Partitioned,
		})
	}
}

// SetTwoFactorCookie sets the signed two-factor challenge cookie.
func SetTwoFactorCookie(w http.ResponseWriter, cfg Config, secret string, identifier string, maxAge int) {
	signed := SignCookie(identifier, secret)
	http.SetCookie(w, &http.Cookie{
		Name:        cfg.TwoFactorName(),
		Value:       signed,
		Path:        cfg.Path,
		Domain:      cfg.Domain,
		MaxAge:      maxAge,
		HttpOnly:    true,
		Secure:      cfg.Secure,
		SameSite:    cfg.SameSite,
		Partitioned: cfg.Partitioned,
	})
}

// SetTrustDeviceCookie sets the signed trusted-device cookie.
func SetTrustDeviceCookie(w http.ResponseWriter, cfg Config, secret string, value string, maxAge int) {
	signed := SignCookie(value, secret)
	http.SetCookie(w, &http.Cookie{
		Name:        cfg.TrustDeviceName(),
		Value:       signed,
		Path:        cfg.Path,
		Domain:      cfg.Domain,
		MaxAge:      maxAge,
		HttpOnly:    true,
		Secure:      cfg.Secure,
		SameSite:    cfg.SameSite,
		Partitioned: cfg.Partitioned,
	})
}

// SetSessionDataCookie sets the session_data cache cookie.
func SetSessionDataCookie(w http.ResponseWriter, cfg Config, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:        cfg.SessionDataName(),
		Value:       value,
		Path:        cfg.Path,
		Domain:      cfg.Domain,
		MaxAge:      maxAge,
		HttpOnly:    true,
		Secure:      cfg.Secure,
		SameSite:    cfg.SameSite,
		Partitioned: cfg.Partitioned,
	})
}

// IsDontRemember reports whether the dont_remember cookie is present.
func IsDontRemember(r *http.Request, cfg Config, secret string) bool {
	return IsDontRememberAny(r, cfg, []string{secret})
}

// IsDontRememberAny reports whether the dont_remember cookie is present,
// verifying against any of the provided secrets.
func IsDontRememberAny(r *http.Request, cfg Config, secrets []string) bool {
	c, err := r.Cookie(cfg.DontRememberName())
	if err != nil {
		return false
	}
	val, ok := VerifySignedCookieAny(c.Value, secrets)
	return ok && val == "true"
}

// DeleteSessionCookies clears session-related cookies.
func DeleteSessionCookies(w http.ResponseWriter, cfg Config) {
	expire := &http.Cookie{
		Path:        cfg.Path,
		Domain:      cfg.Domain,
		MaxAge:      -1,
		Expires:     time.Unix(0, 0),
		HttpOnly:    true,
		Secure:      cfg.Secure,
		SameSite:    cfg.SameSite,
		Partitioned: cfg.Partitioned,
	}

	sessionCookie := *expire
	sessionCookie.Name = cfg.SessionTokenName()
	http.SetCookie(w, &sessionCookie)

	sessionDataCookie := *expire
	sessionDataCookie.Name = cfg.SessionDataName()
	http.SetCookie(w, &sessionDataCookie)

	dontRememberCookie := *expire
	dontRememberCookie.Name = cfg.DontRememberName()
	http.SetCookie(w, &dontRememberCookie)
}

// DeleteTwoFactorCookie clears the two-factor challenge cookie.
func DeleteTwoFactorCookie(w http.ResponseWriter, cfg Config) {
	http.SetCookie(w, &http.Cookie{
		Name:        cfg.TwoFactorName(),
		Path:        cfg.Path,
		Domain:      cfg.Domain,
		MaxAge:      -1,
		Expires:     time.Unix(0, 0),
		HttpOnly:    true,
		Secure:      cfg.Secure,
		SameSite:    cfg.SameSite,
		Partitioned: cfg.Partitioned,
	})
}

// DeleteTrustDeviceCookie clears the trusted-device cookie.
func DeleteTrustDeviceCookie(w http.ResponseWriter, cfg Config) {
	http.SetCookie(w, &http.Cookie{
		Name:        cfg.TrustDeviceName(),
		Path:        cfg.Path,
		Domain:      cfg.Domain,
		MaxAge:      -1,
		Expires:     time.Unix(0, 0),
		HttpOnly:    true,
		Secure:      cfg.Secure,
		SameSite:    cfg.SameSite,
		Partitioned: cfg.Partitioned,
	})
}

// GetSessionToken reads and verifies the session token from the request cookies.
func GetSessionToken(r *http.Request, cfg Config, secret string) (string, bool) {
	return GetSessionTokenAny(r, cfg, []string{secret})
}

// GetSessionTokenAny reads and verifies the session token against any of the
// provided secrets (primary first, then rotated/old secrets).
func GetSessionTokenAny(r *http.Request, cfg Config, secrets []string) (string, bool) {
	c, err := r.Cookie(cfg.SessionTokenName())
	if err != nil {
		return "", false
	}
	return VerifySignedCookieAny(c.Value, secrets)
}

// GetTwoFactorCookieAny reads and verifies the two-factor challenge cookie.
func GetTwoFactorCookieAny(r *http.Request, cfg Config, secrets []string) (string, bool) {
	c, err := r.Cookie(cfg.TwoFactorName())
	if err != nil {
		return "", false
	}
	return VerifySignedCookieAny(c.Value, secrets)
}

// GetTrustDeviceCookieAny reads and verifies the trusted-device cookie.
func GetTrustDeviceCookieAny(r *http.Request, cfg Config, secrets []string) (string, bool) {
	c, err := r.Cookie(cfg.TrustDeviceName())
	if err != nil {
		return "", false
	}
	return VerifySignedCookieAny(c.Value, secrets)
}
