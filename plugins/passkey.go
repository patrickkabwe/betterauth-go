package plugins

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

const defaultPasskeyChallengeCookie = "better-auth-passkey"

// PasskeyOptions configures WebAuthn passkey support.
type PasskeyOptions struct {
	RPID                string
	RPDisplayName       string
	RPOrigins           []string
	ChallengeCookieName string
}

type passkeyUser struct {
	user        *types.User
	credentials []gowebauthn.Credential
}

func (u passkeyUser) WebAuthnID() []byte                           { return []byte(u.user.ID) }
func (u passkeyUser) WebAuthnName() string                         { return u.user.Email }
func (u passkeyUser) WebAuthnDisplayName() string                  { return u.user.Name }
func (u passkeyUser) WebAuthnCredentials() []gowebauthn.Credential { return u.credentials }

// Passkey enables WebAuthn passkey registration, sign-in, and management routes.
func Passkey(opts PasskeyOptions) auth.Plugin {
	return basePlugin{
		id: constants.PluginPasskey,
		routes: []auth.PluginRoute{
			rt(http.MethodGet, "/passkey/generate-register-options", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				ext, passkeyUser, ok := passkeyUserFor(c, user)
				if !ok {
					return
				}
				webAuthn, ok := newPasskeyWebAuthn(c, opts)
				if !ok {
					return
				}
				options, session, err := webAuthn.BeginRegistration(passkeyUser)
				if err != nil {
					c.WriteError(apierror.New(http.StatusInternalServerError, constants.CodeInternalServerError, err.Error()))
					return
				}
				if !storePasskeyChallenge(c, opts, "register", session) {
					return
				}
				_ = ext
				c.WriteJSON(http.StatusOK, options)
			}),
			rt(http.MethodPost, "/passkey/verify-registration", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				ext, passkeyUser, ok := passkeyUserFor(c, user)
				if !ok {
					return
				}
				webAuthn, ok := newPasskeyWebAuthn(c, opts)
				if !ok {
					return
				}
				session, ok := consumePasskeyChallenge(c, opts, "register")
				if !ok {
					return
				}
				raw, err := io.ReadAll(io.LimitReader(c.R.Body, 1<<20))
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
				name := passkeyNameFromBody(raw)
				c.R.Body = io.NopCloser(bytes.NewReader(raw))
				credential, err := webAuthn.FinishRegistration(passkeyUser, session, c.R)
				if err != nil {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, err.Error()))
					return
				}
				record, err := passkeyRecordFromCredential(user.ID, name, credential)
				if err != nil {
					c.WriteError(apierror.New(http.StatusInternalServerError, constants.CodeInternalServerError, err.Error()))
					return
				}
				if err := ext.CreatePasskey(c.R.Context(), record); err != nil {
					status := http.StatusInternalServerError
					if errors.Is(err, berrors.ErrAlreadyExists) {
						status = http.StatusConflict
					}
					c.WriteError(apierror.WithCode(status, constants.CodeInvalidRequest))
					return
				}
				c.WriteJSON(http.StatusOK, record)
			}),
			rt(http.MethodGet, "/passkey/generate-authenticate-options", func(c *auth.Context) {
				webAuthn, ok := newPasskeyWebAuthn(c, opts)
				if !ok {
					return
				}
				options, session, err := webAuthn.BeginDiscoverableLogin()
				if err != nil {
					c.WriteError(apierror.New(http.StatusInternalServerError, constants.CodeInternalServerError, err.Error()))
					return
				}
				if !storePasskeyChallenge(c, opts, "authenticate", session) {
					return
				}
				c.WriteJSON(http.StatusOK, options)
			}),
			rt(http.MethodPost, "/passkey/verify-authentication", func(c *auth.Context) {
				ext, ok := requirePasskeyStore(c)
				if !ok {
					return
				}
				webAuthn, ok := newPasskeyWebAuthn(c, opts)
				if !ok {
					return
				}
				session, ok := consumePasskeyChallenge(c, opts, "authenticate")
				if !ok {
					return
				}
				resolvedUserID := ""
				handler := func(rawID []byte, userHandle []byte) (gowebauthn.User, error) {
					credentialID := base64.RawURLEncoding.EncodeToString(rawID)
					passkey, err := ext.FindPasskeyByCredentialID(c.R.Context(), credentialID)
					if err != nil {
						return nil, err
					}
					user, err := c.Auth.Store().FindUserByID(c.R.Context(), passkey.UserID)
					if err != nil {
						return nil, err
					}
					if string(userHandle) != "" && string(userHandle) != user.ID {
						return nil, berrors.ErrNotFound
					}
					resolvedUserID = user.ID
					passkeyUser, err := passkeyUserFromRecords(user, []types.Passkey{*passkey})
					if err != nil {
						return nil, err
					}
					return passkeyUser, nil
				}
				credential, err := webAuthn.FinishDiscoverableLogin(handler, session, c.R)
				if err != nil {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, err.Error()))
					return
				}
				if resolvedUserID == "" {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
				credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
				passkey, err := ext.FindPasskeyByCredentialID(c.R.Context(), credentialID)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
				rawCredential, _ := json.Marshal(credential)
				rawCredentialString := string(rawCredential)
				now := time.Now().UTC()
				_, _ = ext.UpdatePasskey(c.R.Context(), passkey.ID, store.PasskeyUpdate{
					CredentialJSON: &rawCredentialString,
					BackedUp:       &credential.Flags.BackupState,
					UpdatedAt:      &now,
				})
				user, err := c.Auth.Store().FindUserByID(c.R.Context(), resolvedUserID)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				sess, err := c.Auth.NewSession(c, resolvedUserID, true)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeFailedToCreateSession))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]any{"user": user, "session": sess})
			}),
			rt(http.MethodGet, "/passkey/list", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				ext, ok := requirePasskeyStore(c)
				if !ok {
					return
				}
				passkeys, err := ext.ListPasskeysByUserID(c.R.Context(), user.ID)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				c.WriteJSON(http.StatusOK, passkeys)
			}),
			rt(http.MethodPost, "/passkey/update", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				ext, ok := requirePasskeyStore(c)
				if !ok {
					return
				}
				var body struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				}
				if err := c.ParseJSON(&body); err != nil || body.ID == "" {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
					return
				}
				if !userOwnsPasskey(c, ext, user.ID, body.ID) {
					return
				}
				now := time.Now().UTC()
				passkey, err := ext.UpdatePasskey(c.R.Context(), body.ID, store.PasskeyUpdate{Name: &body.Name, UpdatedAt: &now})
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeInvalidRequest))
					return
				}
				c.WriteJSON(http.StatusOK, passkey)
			}),
			rt(http.MethodPost, "/passkey/delete", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				ext, ok := requirePasskeyStore(c)
				if !ok {
					return
				}
				var body struct {
					ID string `json:"id"`
				}
				if err := c.ParseJSON(&body); err != nil || body.ID == "" {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
					return
				}
				if err := ext.DeletePasskey(c.R.Context(), body.ID, user.ID); err != nil {
					c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeInvalidRequest))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
		},
	}
}

func newPasskeyWebAuthn(c *auth.Context, opts PasskeyOptions) (*gowebauthn.WebAuthn, bool) {
	base, err := url.Parse(c.Auth.BaseURL())
	if err != nil {
		c.WriteError(apierror.New(http.StatusInternalServerError, constants.CodeInternalServerError, err.Error()))
		return nil, false
	}
	rpID := opts.RPID
	if rpID == "" {
		rpID = base.Hostname()
	}
	displayName := opts.RPDisplayName
	if displayName == "" {
		displayName = "Better Auth"
	}
	origins := opts.RPOrigins
	if len(origins) == 0 {
		origin := base.Scheme + "://" + base.Host
		origins = []string{origin}
	}
	webAuthn, err := gowebauthn.New(&gowebauthn.Config{RPID: rpID, RPDisplayName: displayName, RPOrigins: origins})
	if err != nil {
		c.WriteError(apierror.New(http.StatusInternalServerError, constants.CodeInternalServerError, err.Error()))
		return nil, false
	}
	return webAuthn, true
}

func requirePasskeyStore(c *auth.Context) (store.ExtStore, bool) {
	ext, ok := auth.ExtStore(c.Auth.Store())
	if !ok {
		c.WriteError(apierror.New(http.StatusInternalServerError, constants.CodeInternalServerError, "Passkey requires store.ExtStore"))
		return nil, false
	}
	return ext, true
}

func passkeyUserFor(c *auth.Context, user *types.User) (store.ExtStore, passkeyUser, bool) {
	ext, ok := requirePasskeyStore(c)
	if !ok {
		return nil, passkeyUser{}, false
	}
	passkeys, err := ext.ListPasskeysByUserID(c.R.Context(), user.ID)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return nil, passkeyUser{}, false
	}
	resolvedPasskeyUser, err := passkeyUserFromRecords(user, passkeys)
	if err != nil {
		c.WriteError(apierror.New(http.StatusInternalServerError, constants.CodeInternalServerError, err.Error()))
		return nil, passkeyUser{}, false
	}
	return ext, resolvedPasskeyUser, true
}

func passkeyUserFromRecords(user *types.User, records []types.Passkey) (passkeyUser, error) {
	credentials := make([]gowebauthn.Credential, 0, len(records))
	for _, record := range records {
		var credential gowebauthn.Credential
		if err := json.Unmarshal([]byte(record.CredentialJSON), &credential); err != nil {
			return passkeyUser{}, err
		}
		credentials = append(credentials, credential)
	}
	return passkeyUser{user: user, credentials: credentials}, nil
}

func storePasskeyChallenge(c *auth.Context, opts PasskeyOptions, typ string, session *gowebauthn.SessionData) bool {
	raw, err := json.Marshal(session)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	token, err := id.Generate(32)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	if err := c.Auth.CreateVerification(c.R.Context(), "passkey:"+typ+":"+token, string(raw), 5*time.Minute); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	http.SetCookie(c.W, &http.Cookie{
		Name:     passkeyChallengeCookie(opts),
		Value:    typ + ":" + token,
		Path:     c.Auth.BasePath(),
		MaxAge:   300,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return true
}

func consumePasskeyChallenge(c *auth.Context, opts PasskeyOptions, typ string) (gowebauthn.SessionData, bool) {
	cookie, err := c.R.Cookie(passkeyChallengeCookie(opts))
	if err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "Passkey challenge is missing"))
		return gowebauthn.SessionData{}, false
	}
	prefix := typ + ":"
	if !strings.HasPrefix(cookie.Value, prefix) {
		c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "Passkey challenge type mismatch"))
		return gowebauthn.SessionData{}, false
	}
	verification, err := c.Auth.ConsumeVerification(c.R.Context(), "passkey:"+typ+":"+strings.TrimPrefix(cookie.Value, prefix))
	if err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "Passkey challenge expired"))
		return gowebauthn.SessionData{}, false
	}
	http.SetCookie(c.W, &http.Cookie{Name: passkeyChallengeCookie(opts), Value: "", Path: c.Auth.BasePath(), MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	var session gowebauthn.SessionData
	if err := json.Unmarshal([]byte(verification.Value), &session); err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
		return gowebauthn.SessionData{}, false
	}
	return session, true
}

func passkeyChallengeCookie(opts PasskeyOptions) string {
	if opts.ChallengeCookieName != "" {
		return opts.ChallengeCookieName
	}
	return defaultPasskeyChallengeCookie
}

func passkeyRecordFromCredential(userID string, name string, credential *gowebauthn.Credential) (*types.Passkey, error) {
	raw, err := json.Marshal(credential)
	if err != nil {
		return nil, err
	}
	recordID, err := id.Generate(32)
	if err != nil {
		return nil, err
	}
	transports := make([]string, 0, len(credential.Transport))
	for _, transport := range credential.Transport {
		transports = append(transports, string(transport))
	}
	now := time.Now().UTC()
	return &types.Passkey{
		ID: recordID, UserID: userID, Name: name,
		CredentialID:   base64.RawURLEncoding.EncodeToString(credential.ID),
		CredentialJSON: string(raw),
		Transports:     strings.Join(transports, ","),
		BackedUp:       credential.Flags.BackupState,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, nil
}

func passkeyNameFromBody(raw []byte) string {
	var body struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(raw, &body)
	return body.Name
}

func userOwnsPasskey(c *auth.Context, ext store.ExtStore, userID string, passkeyID string) bool {
	passkeys, err := ext.ListPasskeysByUserID(c.R.Context(), userID)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	for _, passkey := range passkeys {
		if passkey.ID == passkeyID {
			return true
		}
	}
	c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeInvalidRequest))
	return false
}
