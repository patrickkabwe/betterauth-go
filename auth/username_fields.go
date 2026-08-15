package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
)

var defaultUsernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.]+$`)

// UsernameRules describes the username plugin validation rules needed by core
// routes that accept plugin-owned user fields.
type UsernameRules struct {
	MinUsernameLength int
	MaxUsernameLength int
}

// UsernameRulesPlugin exposes username plugin rules to core auth routes.
type UsernameRulesPlugin interface {
	UsernameRules() UsernameRules
}

func (r UsernameRules) normalized() UsernameRules {
	out := r
	if out.MinUsernameLength == 0 {
		out.MinUsernameLength = 3
	}
	if out.MaxUsernameLength == 0 {
		out.MaxUsernameLength = 30
	}
	return out
}

func (a *Auth) usernameRules() (UsernameRules, bool) {
	for _, plugin := range a.cfg.plugins {
		if plugin.ID() != constants.PluginUsername {
			continue
		}
		if rulesPlugin, ok := plugin.(UsernameRulesPlugin); ok {
			return rulesPlugin.UsernameRules().normalized(), true
		}
		return UsernameRules{}.normalized(), true
	}
	return UsernameRules{}, false
}

func (a *Auth) usernameAdditionalFromRaw(ctx context.Context, raw map[string]json.RawMessage, currentUserID string, create bool) (map[string]any, *apierror.Error) {
	rules, ok := a.usernameRules()
	if !ok {
		return nil, nil
	}
	username, hasUsername, err := optionalStringField(raw, constants.FieldUsername)
	if err != nil {
		return nil, apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidUsername)
	}
	displayUsername, hasDisplayUsername, err := optionalStringField(raw, constants.FieldDisplayUsername)
	if err != nil {
		return nil, apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidUsername)
	}
	if !hasUsername && !hasDisplayUsername {
		return nil, nil
	}
	out := make(map[string]any)
	if hasUsername {
		trimmed := strings.TrimSpace(username)
		if !ValidUsername(trimmed, rules) {
			return nil, apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidUsername)
		}
		normalized := strings.ToLower(trimmed)
		existing, err := a.FindUserByAdditional(ctx, constants.FieldUsername, normalized)
		if err == nil && (currentUserID == "" || existing.ID != currentUserID) {
			return nil, apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidUsername)
		}
		if err != nil && !errors.Is(err, berrors.ErrNotFound) {
			return nil, apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError)
		}
		out[constants.FieldUsername] = normalized
		if hasDisplayUsername {
			out[constants.FieldDisplayUsername] = displayUsername
		} else if create {
			out[constants.FieldDisplayUsername] = username
		}
		return out, nil
	}
	out[constants.FieldDisplayUsername] = displayUsername
	return out, nil
}

// ValidUsername reports whether username matches Better Auth's default username
// constraints with the configured length bounds.
func ValidUsername(username string, rules UsernameRules) bool {
	rules = rules.normalized()
	return len(username) >= rules.MinUsernameLength &&
		len(username) <= rules.MaxUsernameLength &&
		defaultUsernamePattern.MatchString(username)
}

func optionalStringField(raw map[string]json.RawMessage, key string) (string, bool, error) {
	value, ok := raw[key]
	if !ok {
		return "", false, nil
	}
	var out string
	if err := json.Unmarshal(value, &out); err != nil {
		return "", true, err
	}
	return out, true, nil
}
