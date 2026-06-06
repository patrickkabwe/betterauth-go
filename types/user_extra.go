package types

import "encoding/json"

// UserWithFields is the API representation of a user including additional fields.
func UserWithFields(u *User) map[string]any {
	if u == nil {
		return nil
	}
	out := map[string]any{
		"id":            u.ID,
		"name":          u.Name,
		"email":         u.Email,
		"emailVerified": u.EmailVerified,
		"image":         u.Image,
		"createdAt":     u.CreatedAt,
		"updatedAt":     u.UpdatedAt,
	}
	for k, v := range u.Additional {
		out[k] = v
	}
	return out
}

// CloneUser returns a shallow copy of the user.
func CloneUser(u *User) User {
	if u == nil {
		return User{}
	}
	cp := *u
	if u.Additional != nil {
		cp.Additional = make(map[string]any, len(u.Additional))
		for k, v := range u.Additional {
			cp.Additional[k] = v
		}
	}
	return cp
}

// MarshalJSON flattens additional fields into the user object for API responses.
func (u User) MarshalJSON() ([]byte, error) {
	return json.Marshal(UserWithFields(&u))
}

// UnmarshalJSON reads a user object including unknown fields into Additional.
func (u *User) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	type core User
	var base core
	if v, ok := raw["id"]; ok {
		_ = json.Unmarshal(v, &base.ID)
	}
	if v, ok := raw["name"]; ok {
		_ = json.Unmarshal(v, &base.Name)
	}
	if v, ok := raw["email"]; ok {
		_ = json.Unmarshal(v, &base.Email)
	}
	if v, ok := raw["emailVerified"]; ok {
		_ = json.Unmarshal(v, &base.EmailVerified)
	}
	if v, ok := raw["image"]; ok {
		_ = json.Unmarshal(v, &base.Image)
	}
	if v, ok := raw["createdAt"]; ok {
		_ = json.Unmarshal(v, &base.CreatedAt)
	}
	if v, ok := raw["updatedAt"]; ok {
		_ = json.Unmarshal(v, &base.UpdatedAt)
	}
	*u = User(base)
	known := map[string]bool{"id": true, "name": true, "email": true, "emailVerified": true, "image": true, "createdAt": true, "updatedAt": true}
	u.Additional = make(map[string]any)
	for k, v := range raw {
		if known[k] {
			continue
		}
		var anyVal any
		if err := json.Unmarshal(v, &anyVal); err == nil {
			u.Additional[k] = anyVal
		}
	}
	return nil
}

// MergeAdditionalFields copies additional field values into dst from raw JSON values.
func MergeAdditionalFields(dst map[string]any, raw map[string]json.RawMessage) {
	if dst == nil {
		return
	}
	for k, v := range raw {
		var anyVal any
		if err := json.Unmarshal(v, &anyVal); err == nil {
			dst[k] = anyVal
		}
	}
}
