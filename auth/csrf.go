package auth

import (
	"net/http"
	"net/url"
)

// csrfAllowed implements origin-based CSRF protection. For state-changing
// requests (anything other than GET/HEAD/OPTIONS) it verifies that the Origin
// header — or the Referer when Origin is absent — points at a trusted origin.
//
// Requests without an Origin or Referer header are allowed: browsers always
// send Origin on cross-site state-changing requests, so their absence implies a
// non-browser client (e.g. a bearer-token API call) that is not subject to CSRF.
//
// The check is skipped entirely when advanced.disableCSRFCheck is set or when
// no trusted origins are configured.
func (a *Auth) csrfAllowed(r *http.Request) bool {
	if a.cfg.csrfDisabled {
		return true
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if len(a.cfg.trustedOrigins) == 0 && len(a.cfg.trustedOriginPatterns) == 0 {
		return true
	}

	if origin := r.Header.Get("Origin"); origin != "" {
		return a.isTrustedOrigin(origin)
	}
	if referer := r.Header.Get("Referer"); referer != "" {
		u, err := url.Parse(referer)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return false
		}
		return a.isTrustedOrigin(u.Scheme + "://" + u.Host)
	}
	// No browser origin information: not a forgeable cross-site request.
	return true
}
