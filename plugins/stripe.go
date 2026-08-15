package plugins

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
)

const (
	stripeCustomerIDField     = "stripeCustomerId"
	stripeSubscriptionIDField = "stripeSubscriptionId"
)

// StripePlan describes a billable plan.
type StripePlan struct {
	Name                  string
	PriceID               string
	AnnualDiscountPriceID string
	SeatPriceID           string
}

// StripeOptions configures Stripe billing routes.
type StripeOptions struct {
	SecretKey     string
	APIBase       string
	WebhookSecret string
	Plans         []StripePlan
	OnWebhook     func(*auth.Context, map[string]any) error
}

// Stripe enables Stripe checkout, billing portal, subscription, and webhook routes.
func Stripe(opts StripeOptions) auth.Plugin {
	return basePlugin{
		id: constants.PluginStripe,
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/subscription/upgrade", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				var body struct {
					Plan         string         `json:"plan"`
					SuccessURL   string         `json:"successUrl"`
					CancelURL    string         `json:"cancelUrl"`
					Annual       bool           `json:"annual"`
					CustomerType string         `json:"customerType"`
					ReferenceID  string         `json:"referenceId"`
					Seats        int            `json:"seats"`
					Metadata     map[string]any `json:"metadata"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
					return
				}
				priceID := stripePriceID(opts.Plans, body.Plan, body.Annual, false)
				if priceID == "" {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "Unknown Stripe plan"))
					return
				}
				referenceID := firstNonEmpty(body.ReferenceID, user.ID)
				customerType := firstNonEmpty(body.CustomerType, "user")
				quantity := body.Seats
				if quantity < 1 {
					quantity = 1
				}
				form := url.Values{}
				form.Set("mode", "subscription")
				form.Set("success_url", body.SuccessURL)
				form.Set("cancel_url", body.CancelURL)
				form.Set("client_reference_id", referenceID)
				form.Set("line_items[0][price]", priceID)
				form.Set("line_items[0][quantity]", "1")
				form.Set("metadata[referenceId]", referenceID)
				form.Set("metadata[customerType]", customerType)
				form.Set("metadata[plan]", body.Plan)
				stripeSetMetadata(form, "metadata", body.Metadata)
				if seatPriceID := stripePriceID(opts.Plans, body.Plan, false, true); seatPriceID != "" {
					form.Set("line_items[1][price]", seatPriceID)
					form.Set("line_items[1][quantity]", strconv.Itoa(quantity))
				}
				if customerID := auth.UserAdditionalString(user, stripeCustomerIDField); customerID != "" {
					form.Set("customer", customerID)
				} else {
					form.Set("customer_email", user.Email)
				}
				data, err := stripePost(c, opts, "/v1/checkout/sessions", form)
				if err != nil {
					c.WriteError(apierror.New(http.StatusBadGateway, constants.CodeInternalServerError, err.Error()))
					return
				}
				c.WriteJSON(http.StatusOK, data)
			}),
			rt(http.MethodPost, "/subscription/billing-portal", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				var body struct {
					CustomerID string `json:"customerId"`
					ReturnURL  string `json:"returnUrl"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
					return
				}
				customerID := body.CustomerID
				if customerID == "" {
					customerID = auth.UserAdditionalString(user, stripeCustomerIDField)
				}
				if customerID == "" {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "Stripe customer id is required"))
					return
				}
				form := url.Values{}
				form.Set("customer", customerID)
				form.Set("return_url", body.ReturnURL)
				data, err := stripePost(c, opts, "/v1/billing_portal/sessions", form)
				if err != nil {
					c.WriteError(apierror.New(http.StatusBadGateway, constants.CodeInternalServerError, err.Error()))
					return
				}
				c.WriteJSON(http.StatusOK, data)
			}),
			rt(http.MethodGet, "/subscription/list", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				customerID := c.R.URL.Query().Get("customerId")
				if customerID == "" {
					customerID = auth.UserAdditionalString(user, stripeCustomerIDField)
				}
				if customerID == "" {
					c.WriteJSON(http.StatusOK, []any{})
					return
				}
				query := url.Values{}
				query.Set("customer", customerID)
				data, err := stripeGet(c, opts, "/v1/subscriptions", query)
				if err != nil {
					c.WriteError(apierror.New(http.StatusBadGateway, constants.CodeInternalServerError, err.Error()))
					return
				}
				subscriptions, _ := data["data"].([]any)
				c.WriteJSON(http.StatusOK, subscriptions)
			}),
			rt(http.MethodPost, "/subscription/cancel", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				var body struct {
					CustomerID      string `json:"customerId"`
					SubscriptionID  string `json:"subscriptionId"`
					ReturnURL       string `json:"returnUrl"`
					DisableRedirect bool   `json:"disableRedirect"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
					return
				}
				customerID := body.CustomerID
				if customerID == "" {
					customerID = auth.UserAdditionalString(user, stripeCustomerIDField)
				}
				subscriptionID := body.SubscriptionID
				if subscriptionID == "" {
					subscriptionID = auth.UserAdditionalString(user, stripeSubscriptionIDField)
				}
				if customerID == "" || subscriptionID == "" {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "Stripe customer id and subscription id are required"))
					return
				}
				form := url.Values{}
				form.Set("customer", customerID)
				form.Set("return_url", body.ReturnURL)
				form.Set("flow_data[type]", "subscription_cancel")
				form.Set("flow_data[subscription_cancel][subscription]", subscriptionID)
				data, err := stripePost(c, opts, "/v1/billing_portal/sessions", form)
				if err != nil {
					c.WriteError(apierror.New(http.StatusBadGateway, constants.CodeInternalServerError, err.Error()))
					return
				}
				if _, ok := data["redirect"]; !ok {
					data["redirect"] = !body.DisableRedirect
				}
				c.WriteJSON(http.StatusOK, data)
			}),
			rt(http.MethodPost, "/subscription/restore", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				var body struct {
					SubscriptionID string `json:"subscriptionId"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
					return
				}
				subscriptionID := body.SubscriptionID
				if subscriptionID == "" {
					subscriptionID = auth.UserAdditionalString(user, stripeSubscriptionIDField)
				}
				if subscriptionID == "" {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "Stripe subscription id is required"))
					return
				}
				form := url.Values{}
				form.Set("cancel_at_period_end", "false")
				data, err := stripePost(c, opts, "/v1/subscriptions/"+url.PathEscape(subscriptionID), form)
				if err != nil {
					c.WriteError(apierror.New(http.StatusBadGateway, constants.CodeInternalServerError, err.Error()))
					return
				}
				c.WriteJSON(http.StatusOK, data)
			}),
			rt(http.MethodGet, "/subscription/success", func(c *auth.Context) {
				callbackURL := c.R.URL.Query().Get("callbackURL")
				if callbackURL == "" {
					callbackURL = "/"
				}
				c.Redirect(callbackURL)
			}),
			rt(http.MethodPost, "/stripe/webhook", func(c *auth.Context) {
				raw, err := io.ReadAll(io.LimitReader(c.R.Body, 1<<20))
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
				if opts.WebhookSecret != "" && !validStripeSignature(c.R.Header.Get("Stripe-Signature"), raw, opts.WebhookSecret) {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "Invalid Stripe signature"))
					return
				}
				var event map[string]any
				if err := json.Unmarshal(raw, &event); err != nil {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
					return
				}
				if opts.OnWebhook != nil {
					if err := opts.OnWebhook(c, event); err != nil {
						c.WriteError(apierror.New(http.StatusBadGateway, constants.CodeInternalServerError, err.Error()))
						return
					}
				}
				c.WriteJSON(http.StatusOK, map[string]bool{"received": true})
			}),
		},
	}
}

func stripePriceID(plans []StripePlan, planName string, annual bool, seat bool) string {
	for _, plan := range plans {
		if !strings.EqualFold(plan.Name, planName) {
			continue
		}
		if seat {
			return plan.SeatPriceID
		}
		if annual && plan.AnnualDiscountPriceID != "" {
			return plan.AnnualDiscountPriceID
		}
		return plan.PriceID
	}
	return ""
}

func stripeSetMetadata(form url.Values, prefix string, metadata map[string]any) {
	for key, value := range metadata {
		if key == "" || value == nil {
			continue
		}
		form.Set(prefix+"["+key+"]", fmt.Sprint(value))
	}
}

func stripePost(c *auth.Context, opts StripeOptions, path string, form url.Values) (map[string]any, error) {
	return stripeRequest(c, opts, http.MethodPost, path, form)
}

func stripeGet(c *auth.Context, opts StripeOptions, path string, query url.Values) (map[string]any, error) {
	return stripeRequest(c, opts, http.MethodGet, path, query)
}

func stripeRequest(c *auth.Context, opts StripeOptions, method string, path string, values url.Values) (map[string]any, error) {
	if opts.SecretKey == "" {
		return nil, errors.New("stripe secret key is required")
	}
	endpoint := strings.TrimRight(stripeAPIBase(opts), "/") + path
	var reqBody io.Reader
	if method == http.MethodGet {
		if len(values) > 0 {
			endpoint += "?" + values.Encode()
		}
	} else {
		reqBody = strings.NewReader(values.Encode())
	}
	req, err := http.NewRequestWithContext(c.R.Context(), method, endpoint, reqBody)
	if err != nil {
		return nil, err
	}
	if method != http.MethodGet {
		req.Header.Set(constants.HeaderContentType, "application/x-www-form-urlencoded")
	}
	req.Header.Set(constants.HeaderAuthorization, "Bearer "+opts.SecretKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, apierror.New(resp.StatusCode, constants.CodeInternalServerError, string(body))
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return data, nil
}

func stripeAPIBase(opts StripeOptions) string {
	if opts.APIBase != "" {
		return opts.APIBase
	}
	return "https://api.stripe.com"
}

func validStripeSignature(header string, payload []byte, secret string) bool {
	parts := strings.Split(header, ",")
	timestamp := ""
	signatures := make([]string, 0)
	for _, part := range parts {
		keyValue := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(keyValue) != 2 {
			continue
		}
		switch keyValue[0] {
		case "t":
			timestamp = keyValue[1]
		case "v1":
			signatures = append(signatures, keyValue[1])
		}
	}
	if timestamp == "" || len(signatures) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	for _, signature := range signatures {
		if hmac.Equal([]byte(signature), []byte(expected)) {
			return true
		}
	}
	return false
}
