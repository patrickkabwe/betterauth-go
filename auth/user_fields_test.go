package auth

import (
	"encoding/json"
	"testing"
)

func TestParseAdditionalUserInput(t *testing.T) {
	raw := map[string]json.RawMessage{
		"role": json.RawMessage(`"admin"`),
		"age":  json.RawMessage(`42`),
	}
	fields := map[string]AdditionalFieldDef{
		"role": {Type: "string"},
		"age":  {Type: "number"},
	}
	out, err := parseAdditionalUserInput(fields, raw, "update")
	if err != nil || out["role"] != "admin" || out["age"] != float64(42) {
		t.Fatalf("out=%v err=%v", out, err)
	}
}

func TestParseAdditionalUserRejectsNonInputField(t *testing.T) {
	input := false
	fields := map[string]AdditionalFieldDef{
		"internal": {Type: "string", Input: &input},
	}
	raw := map[string]json.RawMessage{"internal": json.RawMessage(`"x"`)}
	out, err := parseAdditionalUserInput(fields, raw, "update")
	if err != nil || len(out) != 0 {
		t.Fatalf("out=%v err=%v", out, err)
	}
}

func TestCoerceFieldTypes(t *testing.T) {
	cases := []struct {
		def  AdditionalFieldDef
		raw  string
		want any
	}{
		{AdditionalFieldDef{Type: "boolean"}, `true`, true},
		{AdditionalFieldDef{Type: "json"}, `{"k":"v"}`, map[string]any{"k": "v"}},
	}
	for _, tc := range cases {
		got, err := coerceFieldValue(tc.def, json.RawMessage(tc.raw))
		if err != nil {
			t.Fatalf("type=%s err=%v", tc.def.Type, err)
		}
		if tc.def.Type == "json" {
			m, ok := got.(map[string]any)
			if !ok || m["k"] != "v" {
				t.Fatalf("json got=%v", got)
			}
			continue
		}
		if got != tc.want {
			t.Fatalf("type=%s got=%v want=%v", tc.def.Type, got, tc.want)
		}
	}
}

func TestParseAdditionalRequiredOnCreate(t *testing.T) {
	fields := map[string]AdditionalFieldDef{
		"role": {Type: "string", Required: true},
	}
	_, err := parseAdditionalUserInput(fields, map[string]json.RawMessage{}, "create")
	if err == nil {
		t.Fatal("expected required field error")
	}
}

func TestApplyDefaultAdditionalFields(t *testing.T) {
	fields := map[string]AdditionalFieldDef{
		"role": {DefaultValue: "user"},
	}
	out := applyDefaultAdditionalFields(nil, fields)
	if out["role"] != "user" {
		t.Fatalf("out=%v", out)
	}
}
