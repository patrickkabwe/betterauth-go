package auth

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/store/memory"
	"github.com/patrickkabwe/betterauth-go/types"
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

func TestFindUserByAdditionalUsesOptionalStoreFinderThroughHooks(t *testing.T) {
	finder := &testAdditionalFinderStore{
		Store: memory.New(),
		user:  &types.User{ID: "found-user", Email: "found@example.com"},
	}
	a, err := New(Config{
		Secret: "test-secret-key-for-cookie-signing",
		Store:  finder,
		DatabaseHooks: DatabaseHooksConfig{
			User: &UserDatabaseHooks{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := a.FindUserByAdditional(context.Background(), constants.FieldUsername, "alice")
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if user.ID != "found-user" || !finder.called {
		t.Fatalf("finder not used: user=%+v called=%v", user, finder.called)
	}
}

type testAdditionalFinderStore struct {
	*memory.Store
	called bool
	user   *types.User
}

func (s *testAdditionalFinderStore) FindUserByAdditional(_ context.Context, _ string, _ any) (*types.User, error) {
	s.called = true
	return s.user, nil
}
