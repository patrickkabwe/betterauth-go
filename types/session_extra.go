package types

import "encoding/json"

// SessionWithFields is the API representation of a session including additional fields.
func SessionWithFields(s *Session) map[string]any {
	if s == nil {
		return nil
	}
	out := map[string]any{
		"id":        s.ID,
		"token":     s.Token,
		"userId":    s.UserID,
		"expiresAt": s.ExpiresAt,
		"createdAt": s.CreatedAt,
		"updatedAt": s.UpdatedAt,
	}
	if s.IPAddress != "" {
		out["ipAddress"] = s.IPAddress
	}
	if s.UserAgent != "" {
		out["userAgent"] = s.UserAgent
	}
	for k, v := range s.Additional {
		out[k] = v
	}
	return out
}

// MarshalJSON flattens additional fields into the session object for API responses.
func (s Session) MarshalJSON() ([]byte, error) {
	return json.Marshal(SessionWithFields(&s))
}
