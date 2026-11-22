package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	stderrors "errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/oauthcrypto"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

func authenticateOAuthClient(c *auth.Context, ext store.ExtStore, clientID, clientSecret string) (*types.OAuthClient, bool) {
	if clientID == "" {
		c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeInvalidClient, "client authentication failed"))
		return nil, false
	}
	client, err := ext.FindOAuthClientByClientID(c.R.Context(), clientID)
	if err != nil || (client.ClientSecret != "" && !secretsEqual(client.ClientSecret, clientSecret)) {
		c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeInvalidClient, "client authentication failed"))
		return nil, false
	}
	return client, true
}

// resolveOAuthClient authenticates the request's client. When a client_assertion
// is present it uses RFC 7523 private_key_jwt (verifyClientAssertion); otherwise
// it falls back to client_secret (authenticateOAuthClient). On failure it writes
// the error and returns ok=false.
func resolveOAuthClient(c *auth.Context, ext store.ExtStore, clientID, clientSecret, assertion, assertionType string) (*types.OAuthClient, bool) {
	if assertion != "" {
		return verifyClientAssertion(c, ext, assertion, assertionType, clientID)
	}
	return authenticateOAuthClient(c, ext, clientID, clientSecret)
}

// verifyClientAssertion authenticates a confidential client with an RFC 7523
// private_key_jwt assertion. It mirrors Better Auth's verifyClientAssertion +
// consumeClientAssertion: it checks the assertion type and signing algorithm,
// looks the client up by the assertion's sub/iss, verifies the signature against
// the client's registered JWK set, enforces the iss/sub/aud/exp/iat claims, and
// consumes the jti once (replay protection via oauthClientAssertion). On any
// failure it writes an invalid_client error and returns ok=false.
func verifyClientAssertion(c *auth.Context, ext store.ExtStore, assertion, assertionType, clientIDHint string) (*types.OAuthClient, bool) {
	fail := func(msg string) (*types.OAuthClient, bool) {
		c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeInvalidClient, msg))
		return nil, false
	}
	if assertionType != clientAssertionType {
		return fail("unsupported client_assertion_type")
	}

	// Read sub/iss from the unverified payload to find the client (and its keys).
	unverified, err := oauthcrypto.UnverifiedClaims(assertion)
	if err != nil {
		return fail("malformed client assertion")
	}
	clientID, _ := unverified["sub"].(string)
	if clientID == "" {
		clientID, _ = unverified["iss"].(string)
	}
	if clientID == "" {
		return fail("client assertion must contain sub or iss claim identifying the client")
	}
	if clientIDHint != "" && clientIDHint != clientID {
		return fail("client_id in body does not match assertion sub/iss")
	}

	client, err := ext.FindOAuthClientByClientID(c.R.Context(), clientID)
	if err != nil {
		return fail("client not found")
	}
	if client.Disabled {
		return fail("client is disabled")
	}
	if client.TokenEndpointAuthMethod != "private_key_jwt" {
		return fail("client is not registered for private_key_jwt authentication")
	}

	keys, err := clientAssertionKeys(client)
	if err != nil {
		return fail(err.Error())
	}
	claims, err := oauthcrypto.VerifyJWSWithJWKS(assertion, keys, oauthcrypto.ClientAssertionAlgorithms())
	if err != nil {
		return fail("client assertion signature verification failed")
	}

	// RFC 7523 §3: iss and sub both identify the client.
	if iss, _ := claims["iss"].(string); iss != clientID {
		return fail("client assertion iss must equal the client id")
	}
	if sub, _ := claims["sub"].(string); sub != clientID {
		return fail("client assertion sub must equal the client id")
	}
	if !consumeClientAssertion(c, ext, claims, clientID) {
		return nil, false
	}
	return client, true
}

// clientAssertionKeys resolves the client's public JWK set for signature
// verification: an inline `jwks` JSON Web Key Set, or a `jwks_uri` fetched over
// HTTPS. It returns the key list (RFC 7517 `keys` array as maps).
func clientAssertionKeys(client *types.OAuthClient) ([]map[string]any, error) {
	if client.JWKS != "" {
		keys, err := parseJWKSet([]byte(client.JWKS))
		if err != nil {
			return nil, stderrors.New("invalid client jwks")
		}
		return keys, nil
	}
	if client.JWKSURI != "" {
		body, err := fetchClientJWKSURI(client.JWKSURI)
		if err != nil {
			return nil, stderrors.New("failed to fetch client JWKS")
		}
		keys, err := parseJWKSet(body)
		if err != nil {
			return nil, stderrors.New("invalid client jwks")
		}
		return keys, nil
	}
	return nil, stderrors.New("client has no JWKS configured")
}

// maxClientJWKSBytes bounds a fetched client JWKS document (RFC 7517 sets are
// small; this matches Better Auth's 64 KiB cap).
const maxClientJWKSBytes = 64 * 1024

// fetchClientJWKSURI fetches a client's JWK set from its jwks_uri. It is an
// SSRF-guarded HTTPS GET: HTTPS only, no redirects, a private/reserved host is
// rejected, the body is size-bounded, and a JSON media type is required. (A
// simplified port of Better Auth's fetchJwksFromUri — no cross-origin discovery
// hooks and no stale-if-error cache.)
func fetchClientJWKSURI(jwksURI string) ([]byte, error) {
	parsed, err := url.Parse(jwksURI)
	if err != nil || parsed.Scheme != "https" {
		return nil, stderrors.New("jwks_uri must use HTTPS")
	}
	if parsed.User != nil || strings.Contains(jwksURI, "#") {
		return nil, stderrors.New("jwks_uri must not contain credentials or a fragment")
	}
	if isPrivateJWKSHost(parsed.Hostname()) {
		return nil, stderrors.New("jwks_uri must not point to a private or reserved address")
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return stderrors.New("jwks_uri must not redirect")
		},
		// Resolve and validate the target at dial time, then connect to the
		// exact IP checked. This closes the DNS-rebinding hole a hostname-only
		// check leaves open: a public name that resolves to an internal address
		// is rejected, and the validated IP is pinned so it cannot change
		// between the check and the connection.
		Transport: &http.Transport{DialContext: safeJWKSDialContext},
	}
	req, err := http.NewRequest(http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, stderrors.New("jwks_uri returned a non-200 status")
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
		return nil, stderrors.New("jwks_uri response must use a JSON media type")
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxClientJWKSBytes+1))
}

// isPrivateJWKSHost reports whether a hostname is obviously not publicly
// routable — a fast syntactic reject for loopback names and literal private IPs.
// Names are resolved and re-checked at dial time by safeJWKSDialContext.
func isPrivateJWKSHost(host string) bool {
	host = strings.Trim(host, "[]")
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") ||
		strings.HasSuffix(lower, ".local") || strings.HasSuffix(lower, ".internal") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false // a public name; its resolved IPs are validated at dial time
	}
	return isReservedIP(ip)
}

// isReservedIP reports whether an IP is loopback, private, link-local,
// unspecified, or the cloud metadata address — i.e. not a safe SSRF target.
func isReservedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() ||
		ip.Equal(net.ParseIP("169.254.169.254"))
}

// safeJWKSDialContext resolves the destination host, refuses to connect when
// any resolved address is private or reserved, and dials the validated IP
// directly so the address cannot be swapped (DNS rebinding) after the check.
func safeJWKSDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if isReservedIP(ip.IP) {
			return nil, stderrors.New("jwks_uri resolves to a private or reserved address")
		}
	}
	if len(ips) == 0 {
		return nil, stderrors.New("jwks_uri host did not resolve")
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

// parseJWKSet parses an RFC 7517 `{"keys":[...]}` document into a slice of JWK
// maps, rejecting an empty set.
func parseJWKSet(raw []byte) ([]map[string]any, error) {
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, err
	}
	if len(set.Keys) == 0 {
		return nil, stderrors.New("empty jwk set")
	}
	return set.Keys, nil
}

// consumeClientAssertion enforces the RFC 7523 §3 assertion-hygiene claims
// (aud/exp/iat) and single-use jti replay protection, mirroring Better Auth's
// consumeClientAssertion. The jti tombstone id is a digest of the namespaced
// jti, inserted under the primary key so a cross-worker replay fails atomically.
func consumeClientAssertion(c *auth.Context, ext store.ExtStore, claims jwt.MapClaims, clientID string) bool {
	fail := func(msg string) bool {
		c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeInvalidClient, msg))
		return false
	}

	// aud MUST include the token endpoint (or the issuer).
	accepted := map[string]bool{
		endpointURL(c, "/oauth2/token"): true,
		c.Auth.BaseURL():                true,
	}
	audOK := false
	for _, a := range audienceValues(claims["aud"]) {
		if accepted[a] {
			audOK = true
			break
		}
	}
	if !audOK {
		return fail("client assertion aud does not match the endpoint")
	}

	now := time.Now().Unix()
	maxLifetime := int64(assertionMaxLifetime / time.Second)
	expF, ok := claims["exp"].(float64)
	if !ok {
		return fail("client assertion must include exp claim")
	}
	exp := int64(expF)
	if exp <= now {
		return fail("client assertion has expired")
	}
	if exp-now > maxLifetime {
		return fail("client assertion exp is too far in the future")
	}
	if iatF, ok := claims["iat"].(float64); ok {
		if now-int64(iatF) > maxLifetime {
			return fail("client assertion iat is too far in the past")
		}
	}

	jti, _ := claims["jti"].(string)
	if jti == "" {
		return fail("client assertion must include jti claim")
	}

	// Single-use: the id is a digest of `private_key_jwt:<clientId>:<jti>`, so the
	// same jti can recur across clients but never within one. A duplicate primary
	// key means replay.
	sum := sha256.Sum256([]byte("private_key_jwt:" + clientID + ":" + jti))
	jtiID := hex.EncodeToString(sum[:])
	err := ext.CreateOAuthClientAssertion(c.R.Context(), &types.OAuthClientAssertion{
		ID:        jtiID,
		ExpiresAt: time.Unix(exp, 0).UTC(),
	})
	if stderrors.Is(err, berrors.ErrAlreadyExists) {
		return fail("client assertion jti has already been used")
	}
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	return true
}

// audienceValues normalizes a JWT `aud` claim (a string or array of strings)
// into a slice.
func audienceValues(aud any) []string {
	switch v := aud.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, a := range v {
			if s, ok := a.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// oauthClientMayIntrospect reports whether the introspecting client is allowed
// to see a token's metadata: it issued the token, or it is linked to one of the
// token's audience resources. Otherwise the caller gets {active:false}.
