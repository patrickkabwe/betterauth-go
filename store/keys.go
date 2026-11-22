package store

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

// TeamMembershipKey derives the unique teamMember.membershipKey the way Better
// Auth does: base64url (no padding) of SHA-256 over JSON.stringify([teamId, userId]).
// It enforces one membership per (team, user) via the teamMember unique index.
func TeamMembershipKey(teamID, userID string) string {
	payload, _ := json.Marshal([]string{teamID, userID})
	sum := sha256.Sum256(payload)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
