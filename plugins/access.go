package plugins

import "fmt"

// AccessConnector controls how multiple requested permissions are evaluated.
type AccessConnector string

const (
	AccessAND AccessConnector = "AND"
	AccessOR  AccessConnector = "OR"
)

// AccessResponse mirrors Better Auth's access-control authorization result.
type AccessResponse struct {
	Success bool
	Error   string
}

// AccessRole is a pure permission authorizer.
type AccessRole struct {
	Statements map[string][]string
}

// NewAccessRole creates an access-control role from resource/action statements.
func NewAccessRole(statements map[string][]string) AccessRole {
	copied := make(map[string][]string, len(statements))
	for resource, actions := range statements {
		copiedActions := make([]string, len(actions))
		copy(copiedActions, actions)
		copied[resource] = copiedActions
	}
	return AccessRole{Statements: copied}
}

// Authorize checks requested resource actions against the role statements.
func (r AccessRole) Authorize(request map[string][]string, connector AccessConnector) AccessResponse {
	if connector != AccessOR {
		connector = AccessAND
	}
	authorizedResource := false
	for resource, actions := range request {
		allowed, ok := r.Statements[resource]
		if !ok {
			if connector == AccessAND {
				return AccessResponse{Success: false, Error: fmt.Sprintf("You are not allowed to access resource: %s", resource)}
			}
			continue
		}
		authorized := accessActionsAllowed(allowed, actions, connector)
		if authorized {
			authorizedResource = true
		}
		if authorized && connector == AccessOR {
			return AccessResponse{Success: true}
		}
		if !authorized && connector == AccessAND {
			return AccessResponse{Success: false, Error: fmt.Sprintf("unauthorized to access resource %q", resource)}
		}
	}
	if authorizedResource {
		return AccessResponse{Success: true}
	}
	return AccessResponse{Success: false, Error: "Not authorized"}
}

// AccessControl creates roles constrained to a common statement shape.
type AccessControl struct {
	Statements map[string][]string
}

// CreateAccessControl creates an access-control factory.
func CreateAccessControl(statements map[string][]string) AccessControl {
	return AccessControl{Statements: NewAccessRole(statements).Statements}
}

// NewRole creates a role from a subset of the access-control statements.
func (c AccessControl) NewRole(statements map[string][]string) AccessRole {
	return NewAccessRole(statements)
}

func accessActionsAllowed(allowed []string, requested []string, connector AccessConnector) bool {
	if len(requested) == 0 {
		return false
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, action := range allowed {
		allowedSet[action] = struct{}{}
	}
	for _, action := range requested {
		_, ok := allowedSet[action]
		if ok && connector == AccessOR {
			return true
		}
		if !ok && connector == AccessAND {
			return false
		}
	}
	return connector == AccessAND
}
