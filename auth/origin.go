package auth

import "strings"

// isTrustedOrigin reports whether the given Origin/URL is allowed. It matches
// exact trusted origins as well as wildcard patterns configured in
// TrustedOrigins, e.g. "https://*.example.com" or "*" (allow any).
func (a *Auth) isTrustedOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	if a.cfg.trustedOrigins[origin] {
		return true
	}
	for _, pattern := range a.cfg.trustedOriginPatterns {
		if matchOriginPattern(pattern, origin) {
			return true
		}
	}
	return false
}

// matchOriginPattern matches an origin against a pattern that may contain "*"
// wildcards. "*" alone matches anything. A leading "*." matches any subdomain.
func matchOriginPattern(pattern, origin string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == origin
	}
	// Split on "*" and ensure each literal segment appears in order, anchored
	// at the start and end.
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(origin[pos:], part)
		if idx < 0 {
			return false
		}
		if i == 0 && idx != 0 {
			// First literal segment must anchor at the start.
			return false
		}
		pos += idx + len(part)
	}
	// Last segment must anchor at the end unless the pattern ended with "*".
	if last := parts[len(parts)-1]; last != "" {
		return strings.HasSuffix(origin, last)
	}
	return true
}
