package plugins_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/types"
)

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// newDeviceAuth wires the OIDC provider together with the device-authorization
// plugin, which supplies the /device/* endpoints the oauth-provider device_code
// grant redeems against.
func newDeviceAuth(t *testing.T) *auth.Auth {
	t.Helper()
	return newTestAuth(t,
		plugins.OIDCProvider(plugins.OIDCProviderOptions{}),
		plugins.DeviceAuthorization(plugins.DeviceAuthorizationOptions{}),
	)
}

// requestDeviceCode issues a device code bound to clientID + scope.
func requestDeviceCode(t *testing.T, a *auth.Auth, clientID, scope string) (deviceCode, userCode string) {
	t.Helper()
	w := post(t, a, "/device/code", `{"client_id":"`+clientID+`","scope":"`+scope+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("device/code status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.DeviceCode == "" || resp.UserCode == "" {
		t.Fatalf("device/code response: %s", w.Body.String())
	}
	return resp.DeviceCode, resp.UserCode
}

func pollDeviceToken(t *testing.T, a *auth.Auth, deviceCode, clientID string) (int, string) {
	t.Helper()
	body := `{"grant_type":"` + deviceGrantType + `","device_code":"` + deviceCode + `","client_id":"` + clientID + `"}`
	w := post(t, a, "/oauth2/token", body)
	return w.Code, w.Body.String()
}

func TestOIDCDeviceCodeGrant(t *testing.T) {
	a := newDeviceAuth(t)
	cookies := signUpPluginUser(t, a, "device-ok@example.com")
	user := currentPluginUser(t, a, cookies)
	clientID := registerOAuthClient(t, a)

	deviceCode, userCode := requestDeviceCode(t, a, clientID, "openid email")

	// Approve the request as the signed-in user.
	aw := postWithCookies(t, a, "/device/approve", `{"userCode":"`+userCode+`"}`, cookies)
	if aw.Code != http.StatusOK {
		t.Fatalf("device/approve status=%d body=%s", aw.Code, aw.Body.String())
	}

	// The device redeems the code at the OAuth token endpoint.
	code, body := pollDeviceToken(t, a, deviceCode, clientID)
	if code != http.StatusOK {
		t.Fatalf("device token status=%d body=%s", code, body)
	}
	var tr tokenResp
	if err := json.Unmarshal([]byte(body), &tr); err != nil || tr.AccessToken == "" || tr.TokenType != "Bearer" {
		t.Fatalf("device token response: %s", body)
	}

	// The issued access token is a real OAuth access token bound to the user.
	at, err := extStore(t, a).FindOAuthAccessToken(context.Background(), tr.AccessToken)
	if err != nil || at.UserID != user.ID {
		t.Fatalf("access token not bound to user: %+v err=%v", at, err)
	}

	// The code is single-use: a second redemption fails.
	if code2, body2 := pollDeviceToken(t, a, deviceCode, clientID); code2 != http.StatusBadRequest {
		t.Fatalf("replayed device code should fail, got %d %s", code2, body2)
	}
}

func TestOIDCDeviceCodePending(t *testing.T) {
	a := newDeviceAuth(t)
	clientID := registerOAuthClient(t, a)

	deviceCode, _ := requestDeviceCode(t, a, clientID, "openid")
	code, body := pollDeviceToken(t, a, deviceCode, clientID)
	if code != http.StatusBadRequest || !strings.Contains(body, "AUTHORIZATION_PENDING") {
		t.Fatalf("expected authorization_pending, got %d %s", code, body)
	}
}

func TestOIDCDeviceCodeSlowDown(t *testing.T) {
	a := newDeviceAuth(t)
	clientID := registerOAuthClient(t, a)
	deviceCode, _ := requestDeviceCode(t, a, clientID, "openid")

	// First poll records lastPolledAt; an immediate second poll is too frequent.
	if code, body := pollDeviceToken(t, a, deviceCode, clientID); code != http.StatusBadRequest {
		t.Fatalf("first poll should be pending, got %d %s", code, body)
	}
	code, body := pollDeviceToken(t, a, deviceCode, clientID)
	if code != http.StatusBadRequest || !strings.Contains(body, "SLOW_DOWN") {
		t.Fatalf("expected slow_down, got %d %s", code, body)
	}
}

func TestOIDCDeviceCodeDenied(t *testing.T) {
	a := newDeviceAuth(t)
	cookies := signUpPluginUser(t, a, "device-deny@example.com")
	clientID := registerOAuthClient(t, a)
	deviceCode, userCode := requestDeviceCode(t, a, clientID, "openid")

	dw := postWithCookies(t, a, "/device/deny", `{"userCode":"`+userCode+`"}`, cookies)
	if dw.Code != http.StatusOK {
		t.Fatalf("device/deny status=%d body=%s", dw.Code, dw.Body.String())
	}
	code, body := pollDeviceToken(t, a, deviceCode, clientID)
	if code != http.StatusBadRequest || !strings.Contains(body, "ACCESS_DENIED") {
		t.Fatalf("expected access_denied, got %d %s", code, body)
	}
}

func TestOIDCDeviceCodeClientMismatch(t *testing.T) {
	a := newDeviceAuth(t)
	cookies := signUpPluginUser(t, a, "device-mismatch@example.com")
	clientID := registerOAuthClient(t, a)
	deviceCode, userCode := requestDeviceCode(t, a, clientID, "openid")
	_ = postWithCookies(t, a, "/device/approve", `{"userCode":"`+userCode+`"}`, cookies)

	// A different client_id cannot redeem a code bound to clientID.
	code, body := pollDeviceToken(t, a, deviceCode, "some-other-client")
	if code != http.StatusBadRequest || !strings.Contains(body, "INVALID_GRANT") {
		t.Fatalf("expected invalid_grant on client mismatch, got %d %s", code, body)
	}
}

func TestOIDCDeviceCodeExpired(t *testing.T) {
	a := newDeviceAuth(t)
	clientID := registerOAuthClient(t, a)

	// Store an already-expired, approved device code directly.
	now := time.Now().UTC()
	_ = extStore(t, a).CreateDeviceCode(context.Background(), &types.DeviceCode{
		ID: "dc-expired", DeviceCode: "expired-device-code", UserCode: "EXPIRE01",
		Status: "approved", UserID: "u1", ClientID: clientID, Scope: "openid",
		ExpiresAt: now.Add(-time.Minute), Interval: 5, CreatedAt: now.Add(-time.Hour),
	})
	code, body := pollDeviceToken(t, a, "expired-device-code", clientID)
	if code != http.StatusBadRequest || !strings.Contains(body, "EXPIRED_TOKEN") {
		t.Fatalf("expected expired_token, got %d %s", code, body)
	}
}
