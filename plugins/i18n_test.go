package plugins_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/plugins"
)

func TestI18nTranslatesErrorFromAcceptLanguage(t *testing.T) {
	a := newTestAuth(t, plugins.I18n(plugins.I18nOptions{
		Translations: map[string]map[string]string{
			"en": {constants.CodeInvalidEmail: "Invalid email"},
			"fr": {constants.CodeInvalidEmail: "Adresse email invalide"},
		},
		Detection: []plugins.LocaleDetectionStrategy{plugins.LocaleFromHeader},
	}))

	req := httptest.NewRequest(http.MethodPost, "/sign-up/email", strings.NewReader(`{"name":"Bad Email","email":"bad","password":"password123"}`))
	req.Header.Set(constants.HeaderContentType, constants.MIMEJSON)
	req.Header.Set("Accept-Language", "en;q=0.5, fr-FR;q=0.9")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["code"] != constants.CodeInvalidEmail || body["message"] != "Adresse email invalide" {
		t.Fatalf("body=%+v", body)
	}
}

func TestI18nTranslatesErrorFromCookie(t *testing.T) {
	a := newTestAuth(t, plugins.I18n(plugins.I18nOptions{
		Translations: map[string]map[string]string{
			"en": {constants.CodeInvalidEmail: "Invalid email"},
			"es": {constants.CodeInvalidEmail: "Correo invalido"},
		},
		Detection:    []plugins.LocaleDetectionStrategy{plugins.LocaleFromCookie},
		LocaleCookie: "lang",
	}))

	req := httptest.NewRequest(http.MethodPost, "/sign-up/email", strings.NewReader(`{"name":"Bad Email","email":"bad","password":"password123"}`))
	req.Header.Set(constants.HeaderContentType, constants.MIMEJSON)
	req.AddCookie(&http.Cookie{Name: "lang", Value: "es"})
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["message"] != "Correo invalido" {
		t.Fatalf("body=%+v", body)
	}
}
