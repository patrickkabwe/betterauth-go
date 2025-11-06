package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/store"
)

const (
	fieldTypeString  = "string"
	fieldTypeNumber  = "number"
	fieldTypeBoolean = "boolean"
	fieldTypeJSON    = "json"
)

// AdditionalFieldDef defines a custom user field.
type AdditionalFieldDef struct {
	Type         string
	Required     bool
	DefaultValue any
	Input        *bool
}

func (d AdditionalFieldDef) allowsInput() bool {
	if d.Input == nil {
		return true
	}
	return *d.Input
}

func parseAdditionalUserInput(fields map[string]AdditionalFieldDef, raw map[string]json.RawMessage, action string) (map[string]any, *apierror.Error) {
	if len(fields) == 0 {
		return nil, nil
	}
	if len(raw) == 0 && action != "create" {
		return nil, nil
	}
	out := make(map[string]any)
	for name, def := range fields {
		if !def.allowsInput() {
			continue
		}
		val, ok := raw[name]
		if !ok {
			if action == "create" && def.Required && def.DefaultValue == nil {
				return nil, apierror.New(http.StatusBadRequest, apierror.CodeMissingField, fmt.Sprintf("%s %s", name, constants.MsgMissingField))
			}
			if def.DefaultValue != nil {
				out[name] = def.DefaultValue
			}
			continue
		}
		parsed, err := coerceFieldValue(def, val)
		if err != nil {
			return nil, apierror.New(http.StatusBadRequest, apierror.CodeInvalidField, err.Error())
		}
		out[name] = parsed
	}
	return out, nil
}

func coerceFieldValue(def AdditionalFieldDef, raw json.RawMessage) (any, error) {
	switch def.Type {
	case fieldTypeString, "":
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		return s, nil
	case fieldTypeNumber:
		var n float64
		if err := json.Unmarshal(raw, &n); err != nil {
			return nil, err
		}
		return n, nil
	case fieldTypeBoolean:
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, err
		}
		return b, nil
	case fieldTypeJSON:
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported field type %q", def.Type)
	}
}

func applyDefaultAdditionalFields(userAdditional map[string]any, fields map[string]AdditionalFieldDef) map[string]any {
	if userAdditional == nil {
		userAdditional = make(map[string]any)
	}
	for name, def := range fields {
		if _, ok := userAdditional[name]; !ok && def.DefaultValue != nil {
			userAdditional[name] = def.DefaultValue
		}
	}
	return userAdditional
}

func mergeUserUpdateFromBody(body map[string]json.RawMessage, fields map[string]AdditionalFieldDef) (store.UserUpdate, map[string]json.RawMessage, *apierror.Error) {
	update := store.UserUpdate{}
	rest := make(map[string]json.RawMessage, len(body))
	for k, v := range body {
		switch k {
		case "name":
			var name string
			_ = json.Unmarshal(v, &name)
			update.Name = &name
		case "image":
			var image *string
			_ = json.Unmarshal(v, &image)
			update.Image = &image
		default:
			rest[k] = v
		}
	}
	additional, err := parseAdditionalUserInput(fields, rest, "update")
	if err != nil {
		return store.UserUpdate{}, nil, err
	}
	if len(additional) > 0 {
		update.Additional = additional
	}
	return update, rest, nil
}
