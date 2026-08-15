package plugins_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/plugins"
)

func TestStripeCreatesCheckoutSession(t *testing.T) {
	var receivedForm string
	stripe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/checkout/sessions" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Header.Get(constants.HeaderAuthorization) != "Bearer sk_test" {
			t.Fatalf("authorization=%q", r.Header.Get(constants.HeaderAuthorization))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		receivedForm = string(body)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "cs_test", "url": "https://checkout.stripe.test/session"})
	}))
	defer stripe.Close()

	a := newTestAuth(t, plugins.Stripe(plugins.StripeOptions{
		SecretKey: "sk_test",
		APIBase:   stripe.URL,
		Plans:     []plugins.StripePlan{{Name: "pro", PriceID: "price_month", AnnualDiscountPriceID: "price_year"}},
	}))
	cookies := signUpPluginUser(t, a, "stripe@example.com")
	resp := postWithCookies(t, a, "/subscription/upgrade", `{"plan":"pro","annual":true,"successUrl":"https://app.test/success","cancelUrl":"https://app.test/cancel"}`, cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(receivedForm, "line_items%5B0%5D%5Bprice%5D=price_year") || !strings.Contains(receivedForm, "mode=subscription") {
		t.Fatalf("form=%s", receivedForm)
	}
}

func TestStripeWebhookVerifiesSignature(t *testing.T) {
	var received bool
	a := newTestAuth(t, plugins.Stripe(plugins.StripeOptions{
		WebhookSecret: "whsec_test",
		OnWebhook: func(_ *auth.Context, _ map[string]any) error {
			received = true
			return nil
		},
	}))

	payload := `{"id":"evt_test","type":"checkout.session.completed"}`
	req := httptest.NewRequest(http.MethodPost, "/stripe/webhook", strings.NewReader(payload))
	req.Header.Set("Stripe-Signature", stripeSignature("123", payload, "whsec_test"))
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !received {
		t.Fatal("webhook callback not called")
	}
}

func TestStripeListsSubscriptionsByCustomer(t *testing.T) {
	var receivedQuery string
	stripe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/subscriptions" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		receivedQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"id": "sub_test", "status": "active"}},
		})
	}))
	defer stripe.Close()

	a := newTestAuth(t, plugins.Stripe(plugins.StripeOptions{
		SecretKey: "sk_test",
		APIBase:   stripe.URL,
	}))
	cookies := signUpPluginUser(t, a, "stripe-list@example.com")
	resp := getWithCookies(t, a, "/subscription/list?customerId=cus_test", cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(receivedQuery, "customer=cus_test") {
		t.Fatalf("query=%s", receivedQuery)
	}
	if !strings.Contains(resp.Body.String(), "sub_test") {
		t.Fatalf("body=%s", resp.Body.String())
	}
}

func TestStripeCancelCreatesBillingPortalFlow(t *testing.T) {
	var receivedForm string
	stripe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/billing_portal/sessions" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		receivedForm = string(body)
		_ = json.NewEncoder(w).Encode(map[string]any{"url": "https://billing.stripe.test/cancel"})
	}))
	defer stripe.Close()

	a := newTestAuth(t, plugins.Stripe(plugins.StripeOptions{
		SecretKey: "sk_test",
		APIBase:   stripe.URL,
	}))
	cookies := signUpPluginUser(t, a, "stripe-cancel@example.com")
	resp := postWithCookies(t, a, "/subscription/cancel", `{"customerId":"cus_test","subscriptionId":"sub_test","returnUrl":"https://app.test/account","disableRedirect":true}`, cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(receivedForm, "flow_data%5Btype%5D=subscription_cancel") ||
		!strings.Contains(receivedForm, "flow_data%5Bsubscription_cancel%5D%5Bsubscription%5D=sub_test") {
		t.Fatalf("form=%s", receivedForm)
	}
	if !strings.Contains(resp.Body.String(), `"redirect":false`) {
		t.Fatalf("body=%s", resp.Body.String())
	}
}

func TestStripeRestoreUpdatesSubscription(t *testing.T) {
	var receivedForm string
	stripe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/subscriptions/sub_test" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		receivedForm = string(body)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "sub_test", "cancel_at_period_end": false})
	}))
	defer stripe.Close()

	a := newTestAuth(t, plugins.Stripe(plugins.StripeOptions{
		SecretKey: "sk_test",
		APIBase:   stripe.URL,
	}))
	cookies := signUpPluginUser(t, a, "stripe-restore@example.com")
	resp := postWithCookies(t, a, "/subscription/restore", `{"subscriptionId":"sub_test"}`, cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if receivedForm != "cancel_at_period_end=false" {
		t.Fatalf("form=%s", receivedForm)
	}
}

func stripeSignature(timestamp string, payload string, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "." + payload))
	return "t=" + timestamp + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}
