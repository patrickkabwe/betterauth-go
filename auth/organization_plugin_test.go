package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/store/memory"
	"github.com/patrickkabwe/betterauth-go/types"
)

func organizationWithTeamsPlugin() auth.Plugin {
	return plugins.Organization(plugins.OrganizationOptions{
		Teams: &plugins.OrganizationTeamsOptions{Enabled: true},
	})
}

func organizationWithTeamsDefaultDisabledPlugin() auth.Plugin {
	disabled := false
	return plugins.Organization(plugins.OrganizationOptions{
		Teams: &plugins.OrganizationTeamsOptions{
			Enabled: true,
			DefaultTeam: &plugins.OrganizationDefaultTeamOptions{
				Enabled: &disabled,
			},
		},
	})
}

func organizationWithTeamsMaximumPlugin(maximumTeams int) auth.Plugin {
	disabled := false
	return plugins.Organization(plugins.OrganizationOptions{
		Teams: &plugins.OrganizationTeamsOptions{
			Enabled:      true,
			MaximumTeams: maximumTeams,
			DefaultTeam: &plugins.OrganizationDefaultTeamOptions{
				Enabled: &disabled,
			},
		},
	})
}

func organizationWithTeamsMemberLimitPlugin(maximumMembersPerTeam int) auth.Plugin {
	disabled := false
	return plugins.Organization(plugins.OrganizationOptions{
		Teams: &plugins.OrganizationTeamsOptions{
			Enabled:               true,
			MaximumMembersPerTeam: maximumMembersPerTeam,
			DefaultTeam: &plugins.OrganizationDefaultTeamOptions{
				Enabled: &disabled,
			},
		},
	})
}

func organizationWithRemovableTeamsPlugin() auth.Plugin {
	disabled := false
	return plugins.Organization(plugins.OrganizationOptions{
		Teams: &plugins.OrganizationTeamsOptions{
			Enabled:               true,
			AllowRemovingAllTeams: true,
			DefaultTeam: &plugins.OrganizationDefaultTeamOptions{
				Enabled: &disabled,
			},
		},
	})
}

func TestOrganizationUpdateMemberRolePersistsRole(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{})}
	})
	ownerCookies := signUp(t, a, "org-owner@example.com")
	_ = signUp(t, a, "org-member@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Acme",
		"slug": "acme",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	memberUser, err := a.Store().FindUserByEmail(context.Background(), "org-member@example.com")
	if err != nil {
		t.Fatalf("find member user: %v", err)
	}
	st := a.Store().(*memory.Store)
	member := types.Member{
		ID:             "member-role-update",
		OrganizationID: org.ID,
		UserID:         memberUser.ID,
		Role:           "member",
		CreatedAt:      time.Now(),
	}
	if err := st.CreateMember(context.Background(), &member); err != nil {
		t.Fatalf("create member: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/update-member-role", map[string]any{
		"organizationId": org.ID,
		"memberId":       member.ID,
		"role":           "admin",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update member role status = %d body=%s", resp.StatusCode, data)
	}
	var updated types.Member
	if err := json.Unmarshal(data, &updated); err != nil {
		t.Fatalf("decode updated member: %v", err)
	}
	if updated.Role != "admin" {
		t.Fatalf("response role = %q, want admin", updated.Role)
	}
	persisted, err := st.FindMemberByID(context.Background(), member.ID)
	if err != nil {
		t.Fatalf("find persisted member: %v", err)
	}
	if persisted.Role != "admin" {
		t.Fatalf("persisted role = %q, want admin", persisted.Role)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/set-active", map[string]any{
		"organizationId": org.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set active organization status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/update-member-role", map[string]any{
		"memberId": member.ID,
		"role":     []string{"member", "admin"},
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update member role with active org status = %d body=%s", resp.StatusCode, data)
	}
	if err := json.Unmarshal(data, &updated); err != nil {
		t.Fatalf("decode updated active member: %v", err)
	}
	if updated.Role != "member,admin" {
		t.Fatalf("active organization response role = %q, want member,admin", updated.Role)
	}
}

func TestOrganizationRemoveMemberDeletesMember(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{})}
	})
	ownerCookies := signUp(t, a, "remove-owner@example.com")
	_ = signUp(t, a, "remove-member@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Remove Org",
		"slug": "remove-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	memberUser, err := a.Store().FindUserByEmail(context.Background(), "remove-member@example.com")
	if err != nil {
		t.Fatalf("find member user: %v", err)
	}
	st := a.Store().(*memory.Store)
	member := types.Member{
		ID:             "member-remove-by-email",
		OrganizationID: org.ID,
		UserID:         memberUser.ID,
		Role:           "member",
		CreatedAt:      time.Now(),
	}
	if err := st.CreateMember(context.Background(), &member); err != nil {
		t.Fatalf("create member: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/remove-member", map[string]any{
		"organizationId":  org.ID,
		"memberIdOrEmail": "remove-member@example.com",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("remove member status = %d body=%s", resp.StatusCode, data)
	}
	var removed struct {
		Member types.Member `json:"member"`
	}
	if err := json.Unmarshal(data, &removed); err != nil {
		t.Fatalf("decode removed member: %v", err)
	}
	if removed.Member.ID != member.ID {
		t.Fatalf("removed member id = %q, want %q", removed.Member.ID, member.ID)
	}
	if _, err := st.FindMemberByID(context.Background(), member.ID); err == nil {
		t.Fatal("expected removed member to be deleted")
	}

	ownerUser, err := a.Store().FindUserByEmail(context.Background(), "remove-owner@example.com")
	if err != nil {
		t.Fatalf("find owner user: %v", err)
	}
	owner, err := st.FindMemberByOrgAndUser(context.Background(), org.ID, ownerUser.ID)
	if err != nil {
		t.Fatalf("find owner member: %v", err)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/remove-member", map[string]any{
		"organizationId": org.ID,
		"memberId":       owner.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("remove only owner status = %d body=%s", resp.StatusCode, data)
	}
	if _, err := st.FindMemberByID(context.Background(), owner.ID); err != nil {
		t.Fatalf("owner should remain after blocked removal: %v", err)
	}
}

func TestOrganizationListMembersRequiresMembershipAndReturnsTotal(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{})}
	})
	ownerCookies := signUp(t, a, "list-owner@example.com")
	outsiderCookies := signUp(t, a, "list-outsider@example.com")
	_ = signUp(t, a, "list-member-a@example.com")
	_ = signUp(t, a, "list-member-b@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "List Org",
		"slug": "list-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	st := a.Store().(*memory.Store)
	memberAUser, err := a.Store().FindUserByEmail(context.Background(), "list-member-a@example.com")
	if err != nil {
		t.Fatalf("find member a: %v", err)
	}
	memberBUser, err := a.Store().FindUserByEmail(context.Background(), "list-member-b@example.com")
	if err != nil {
		t.Fatalf("find member b: %v", err)
	}
	now := time.Now()
	if err := st.CreateMember(context.Background(), &types.Member{
		ID: "list-member-a", OrganizationID: org.ID, UserID: memberAUser.ID,
		Role: "member", CreatedAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("create member a: %v", err)
	}
	if err := st.CreateMember(context.Background(), &types.Member{
		ID: "list-member-b", OrganizationID: org.ID, UserID: memberBUser.ID,
		Role: "admin", CreatedAt: now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("create member b: %v", err)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/list-members?organizationId="+org.ID+"&sortBy=createdAt&sortDirection=desc&limit=2&offset=0", nil, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list members status = %d body=%s", resp.StatusCode, data)
	}
	var listed struct {
		Members []types.Member `json:"members"`
		Total   int            `json:"total"`
	}
	if err := json.Unmarshal(data, &listed); err != nil {
		t.Fatalf("decode listed members: %v", err)
	}
	if listed.Total != 3 {
		t.Fatalf("total = %d, want 3", listed.Total)
	}
	if len(listed.Members) != 2 {
		t.Fatalf("members length = %d, want 2", len(listed.Members))
	}
	if listed.Members[0].ID != "list-member-b" {
		t.Fatalf("first member id = %q, want list-member-b", listed.Members[0].ID)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/list-members?organizationId="+org.ID+"&filterField=role&filterValue=admin", nil, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("filter members status = %d body=%s", resp.StatusCode, data)
	}
	if err := json.Unmarshal(data, &listed); err != nil {
		t.Fatalf("decode filtered members: %v", err)
	}
	if listed.Total != 1 || len(listed.Members) != 1 || listed.Members[0].ID != "list-member-b" {
		t.Fatalf("filtered members = %+v, want only admin member", listed)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/list-members?organizationId="+org.ID+"&filterField=role&filterOperator=in&filterValue=admin&filterValue=member", nil, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("filter members in status = %d body=%s", resp.StatusCode, data)
	}
	if err := json.Unmarshal(data, &listed); err != nil {
		t.Fatalf("decode in-filtered members: %v", err)
	}
	if listed.Total != 2 || len(listed.Members) != 2 {
		t.Fatalf("in-filtered members total=%d len=%d, want total=2 len=2", listed.Total, len(listed.Members))
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/set-active", map[string]any{
		"organizationId": org.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set active organization status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodGet, "/organization/list-members?limit=1", nil, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list members with active org status = %d body=%s", resp.StatusCode, data)
	}
	if err := json.Unmarshal(data, &listed); err != nil {
		t.Fatalf("decode active listed members: %v", err)
	}
	if listed.Total != 3 || len(listed.Members) != 1 {
		t.Fatalf("active listed members total=%d len=%d, want total=3 len=1", listed.Total, len(listed.Members))
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/list-members?organizationId="+org.ID, nil, outsiderCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("outsider list members status = %d body=%s", resp.StatusCode, data)
	}
}

func TestOrganizationLeaveDeletesMemberAndProtectsOnlyOwner(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{})}
	})
	ownerCookies := signUp(t, a, "leave-owner@example.com")
	memberCookies := signUp(t, a, "leave-member@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Leave Org",
		"slug": "leave-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	st := a.Store().(*memory.Store)
	ownerUser, err := a.Store().FindUserByEmail(context.Background(), "leave-owner@example.com")
	if err != nil {
		t.Fatalf("find owner user: %v", err)
	}
	owner, err := st.FindMemberByOrgAndUser(context.Background(), org.ID, ownerUser.ID)
	if err != nil {
		t.Fatalf("find owner member: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/leave", map[string]any{
		"organizationId": org.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("only owner leave status = %d body=%s", resp.StatusCode, data)
	}
	if _, err := st.FindMemberByID(context.Background(), owner.ID); err != nil {
		t.Fatalf("owner should remain after blocked leave: %v", err)
	}

	memberUser, err := a.Store().FindUserByEmail(context.Background(), "leave-member@example.com")
	if err != nil {
		t.Fatalf("find member user: %v", err)
	}
	member := types.Member{
		ID:             "member-leave",
		OrganizationID: org.ID,
		UserID:         memberUser.ID,
		Role:           "member",
		CreatedAt:      time.Now(),
	}
	if err := st.CreateMember(context.Background(), &member); err != nil {
		t.Fatalf("create member: %v", err)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/set-active", map[string]any{
		"organizationId": org.ID,
	}, memberCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set active organization status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/leave", map[string]any{
		"organizationId": org.ID,
	}, memberCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member leave status = %d body=%s", resp.StatusCode, data)
	}
	var left types.Member
	if err := json.Unmarshal(data, &left); err != nil {
		t.Fatalf("decode left member: %v", err)
	}
	if left.ID != member.ID {
		t.Fatalf("left member id = %q, want %q", left.ID, member.ID)
	}
	if _, err := st.FindMemberByID(context.Background(), member.ID); err == nil {
		t.Fatal("expected leaving member to be deleted")
	}
}

func TestOrganizationDeleteCanBeDisabled(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			DisableOrganizationDeletion: true,
		})}
	})
	ownerCookies := signUp(t, a, "delete-disabled-owner@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Delete Disabled Org",
		"slug": "delete-disabled-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/delete", map[string]any{
		"organizationId": org.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled delete organization status = %d body=%s", resp.StatusCode, data)
	}
	if _, err := a.Store().(*memory.Store).FindOrganizationByID(context.Background(), org.ID); err != nil {
		t.Fatalf("organization should remain after disabled delete: %v", err)
	}
}

func TestOrganizationLifecycleHooks(t *testing.T) {
	events := []string{}
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			OrganizationHooks: &plugins.OrganizationHooks{
				BeforeCreateOrganization: func(_ context.Context, data plugins.OrganizationCreateHookData) (*plugins.OrganizationCreateData, error) {
					events = append(events, "before-create")
					updated := data.Organization
					updated.Name = "Hooked Org"
					updated.Slug = "hooked-org"
					return &updated, nil
				},
				AfterCreateOrganization: func(_ context.Context, data plugins.OrganizationCreatedHookData) error {
					if data.Organization.Name != "Hooked Org" || data.Member.Role != constants.RoleOwner || data.User.Email != "hook-owner@example.com" {
						t.Fatalf("after create hook data = %+v", data)
					}
					events = append(events, "after-create")
					return nil
				},
				BeforeUpdateOrganization: func(_ context.Context, data plugins.OrganizationUpdateHookData) (*plugins.OrganizationUpdateData, error) {
					events = append(events, "before-update")
					updated := data.Organization
					updated.Name = "Hooked Updated Org"
					return &updated, nil
				},
				AfterUpdateOrganization: func(_ context.Context, data plugins.OrganizationUpdatedHookData) error {
					if data.Organization.Name != "Hooked Updated Org" || data.Member.Role != constants.RoleOwner {
						t.Fatalf("after update hook data = %+v", data)
					}
					events = append(events, "after-update")
					return nil
				},
				BeforeDeleteOrganization: func(_ context.Context, data plugins.OrganizationDeleteHookData) error {
					if data.Organization.Name != "Hooked Updated Org" {
						t.Fatalf("before delete hook data = %+v", data)
					}
					events = append(events, "before-delete")
					return nil
				},
				AfterDeleteOrganization: func(_ context.Context, data plugins.OrganizationDeleteHookData) error {
					if data.Organization.Name != "Hooked Updated Org" || data.User.Email != "hook-owner@example.com" {
						t.Fatalf("after delete hook data = %+v", data)
					}
					events = append(events, "after-delete")
					return nil
				},
			},
		})}
	})
	ownerCookies := signUp(t, a, "hook-owner@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Original Org",
		"slug": "original-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}
	if org.Name != "Hooked Org" || org.Slug != "hooked-org" {
		t.Fatalf("created organization = %+v", org)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/update", map[string]any{
		"organizationId": org.ID,
		"data": map[string]any{
			"name": "Ignored Update Org",
		},
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update organization status = %d body=%s", resp.StatusCode, data)
	}
	persisted, err := a.Store().(*memory.Store).FindOrganizationByID(context.Background(), org.ID)
	if err != nil {
		t.Fatalf("find updated organization: %v", err)
	}
	if persisted.Name != "Hooked Updated Org" {
		t.Fatalf("persisted organization name = %q", persisted.Name)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/delete", map[string]any{
		"organizationId": org.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete organization status = %d body=%s", resp.StatusCode, data)
	}
	if _, err := a.Store().(*memory.Store).FindOrganizationByID(context.Background(), org.ID); err == nil {
		t.Fatal("organization should be deleted")
	}
	wantEvents := []string{"before-create", "after-create", "before-update", "after-update", "before-delete", "after-delete"}
	if len(events) != len(wantEvents) {
		t.Fatalf("hook events = %+v, want %+v", events, wantEvents)
	}
	for i, want := range wantEvents {
		if events[i] != want {
			t.Fatalf("hook events = %+v, want %+v", events, wantEvents)
		}
	}
}

func TestOrganizationMemberLifecycleHooks(t *testing.T) {
	events := []string{}
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			OrganizationHooks: &plugins.OrganizationHooks{
				BeforeAddMember: func(_ context.Context, data plugins.OrganizationMemberAddHookData) (*plugins.OrganizationMemberCreateData, error) {
					events = append(events, "before-add:"+data.User.Email)
					updated := data.Member
					if data.User.Email == "member-hook-target@example.com" {
						updated.Role = constants.RoleAdmin
					}
					return &updated, nil
				},
				AfterAddMember: func(_ context.Context, data plugins.OrganizationMemberHookData) error {
					events = append(events, "after-add:"+data.User.Email+":"+data.Member.Role)
					return nil
				},
				BeforeUpdateMemberRole: func(_ context.Context, data plugins.OrganizationMemberRoleUpdateHookData) (*plugins.OrganizationMemberRoleUpdateData, error) {
					if data.User.Email != "member-hook-target@example.com" || data.NewRole != "member" {
						t.Fatalf("before update member hook data = %+v", data)
					}
					events = append(events, "before-update:"+data.Member.Role)
					return &plugins.OrganizationMemberRoleUpdateData{Role: "member,admin"}, nil
				},
				AfterUpdateMemberRole: func(_ context.Context, data plugins.OrganizationMemberRoleUpdatedHookData) error {
					if data.User.Email != "member-hook-target@example.com" || data.PreviousRole != constants.RoleAdmin || data.Member.Role != "member,admin" {
						t.Fatalf("after update member hook data = %+v", data)
					}
					events = append(events, "after-update:"+data.Member.Role)
					return nil
				},
				BeforeRemoveMember: func(_ context.Context, data plugins.OrganizationMemberHookData) error {
					if data.User.Email != "member-hook-target@example.com" || data.Member.Role != "member,admin" {
						t.Fatalf("before remove member hook data = %+v", data)
					}
					events = append(events, "before-remove:"+data.User.Email)
					return nil
				},
				AfterRemoveMember: func(_ context.Context, data plugins.OrganizationMemberHookData) error {
					if data.User.Email != "member-hook-target@example.com" || data.Member.Role != "member,admin" {
						t.Fatalf("after remove member hook data = %+v", data)
					}
					events = append(events, "after-remove:"+data.User.Email)
					return nil
				},
			},
		})}
	})
	ownerCookies := signUp(t, a, "member-hook-owner@example.com")
	_ = signUp(t, a, "member-hook-target@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Member Hook Org",
		"slug": "member-hook-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}
	targetUser, err := a.Store().FindUserByEmail(context.Background(), "member-hook-target@example.com")
	if err != nil {
		t.Fatalf("find target user: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/add-member", map[string]any{
		"organizationId": org.ID,
		"userId":         targetUser.ID,
		"role":           "member",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add member status = %d body=%s", resp.StatusCode, data)
	}
	var added types.Member
	if err := json.Unmarshal(data, &added); err != nil {
		t.Fatalf("decode added member: %v", err)
	}
	if added.Role != constants.RoleAdmin {
		t.Fatalf("added member role = %q, want admin", added.Role)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/update-member-role", map[string]any{
		"organizationId": org.ID,
		"memberId":       added.ID,
		"role":           "member",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update member role status = %d body=%s", resp.StatusCode, data)
	}
	var updated types.Member
	if err := json.Unmarshal(data, &updated); err != nil {
		t.Fatalf("decode updated member: %v", err)
	}
	if updated.Role != "member,admin" {
		t.Fatalf("updated member role = %q, want member,admin", updated.Role)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/remove-member", map[string]any{
		"organizationId":  org.ID,
		"memberIdOrEmail": "member-hook-target@example.com",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("remove member status = %d body=%s", resp.StatusCode, data)
	}
	if _, err := a.Store().(*memory.Store).FindMemberByID(context.Background(), added.ID); err == nil {
		t.Fatal("removed member still exists")
	}
	wantEvents := []string{
		"before-add:member-hook-owner@example.com",
		"after-add:member-hook-owner@example.com:owner",
		"before-add:member-hook-target@example.com",
		"after-add:member-hook-target@example.com:admin",
		"before-update:admin",
		"after-update:member,admin",
		"before-remove:member-hook-target@example.com",
		"after-remove:member-hook-target@example.com",
	}
	if len(events) != len(wantEvents) {
		t.Fatalf("member hook events = %+v, want %+v", events, wantEvents)
	}
	for i, want := range wantEvents {
		if events[i] != want {
			t.Fatalf("member hook events = %+v, want %+v", events, wantEvents)
		}
	}
}

func TestOrganizationTeamLifecycleHooks(t *testing.T) {
	events := []string{}
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			Teams: &plugins.OrganizationTeamsOptions{
				Enabled: true,
			},
			OrganizationHooks: &plugins.OrganizationHooks{
				BeforeCreateTeam: func(_ context.Context, data plugins.OrganizationTeamCreateHookData) (*plugins.OrganizationTeamCreateData, error) {
					events = append(events, "before-create-team:"+data.Team.Name)
					updated := data.Team
					if data.Team.Name == "Team Hook Org" {
						updated.Name = "Default Hook Team"
					}
					if data.Team.Name == "Explicit Team" {
						updated.Name = "Explicit Hook Team"
					}
					return &updated, nil
				},
				AfterCreateTeam: func(_ context.Context, data plugins.OrganizationTeamHookData) error {
					events = append(events, "after-create-team:"+data.Team.Name)
					return nil
				},
				BeforeUpdateTeam: func(_ context.Context, data plugins.OrganizationTeamUpdateHookData) (*plugins.OrganizationTeamUpdateData, error) {
					if data.Team.Name != "Explicit Hook Team" || data.Updates.Name != "Ignored Team" {
						t.Fatalf("before update team hook data = %+v", data)
					}
					events = append(events, "before-update-team")
					return &plugins.OrganizationTeamUpdateData{Name: "Updated Hook Team"}, nil
				},
				AfterUpdateTeam: func(_ context.Context, data plugins.OrganizationTeamHookData) error {
					if data.Team.Name != "Updated Hook Team" {
						t.Fatalf("after update team hook data = %+v", data)
					}
					events = append(events, "after-update-team")
					return nil
				},
				BeforeDeleteTeam: func(_ context.Context, data plugins.OrganizationTeamHookData) error {
					if data.Team.Name != "Updated Hook Team" {
						t.Fatalf("before delete team hook data = %+v", data)
					}
					events = append(events, "before-delete-team")
					return nil
				},
				AfterDeleteTeam: func(_ context.Context, data plugins.OrganizationTeamHookData) error {
					if data.Team.Name != "Updated Hook Team" {
						t.Fatalf("after delete team hook data = %+v", data)
					}
					events = append(events, "after-delete-team")
					return nil
				},
				BeforeAddTeamMember: func(_ context.Context, data plugins.OrganizationTeamMemberHookData) error {
					if data.User.Email != "team-hook-target@example.com" || data.Team.Name != "Updated Hook Team" {
						t.Fatalf("before add team member hook data = %+v", data)
					}
					events = append(events, "before-add-team-member")
					return nil
				},
				AfterAddTeamMember: func(_ context.Context, data plugins.OrganizationTeamMemberHookData) error {
					if data.User.Email != "team-hook-target@example.com" || data.TeamMember.ID == "" {
						t.Fatalf("after add team member hook data = %+v", data)
					}
					events = append(events, "after-add-team-member")
					return nil
				},
				BeforeRemoveTeamMember: func(_ context.Context, data plugins.OrganizationTeamMemberHookData) error {
					if data.User.Email != "team-hook-target@example.com" || data.TeamMember.ID == "" {
						t.Fatalf("before remove team member hook data = %+v", data)
					}
					events = append(events, "before-remove-team-member")
					return nil
				},
				AfterRemoveTeamMember: func(_ context.Context, data plugins.OrganizationTeamMemberHookData) error {
					if data.User.Email != "team-hook-target@example.com" || data.TeamMember.ID == "" {
						t.Fatalf("after remove team member hook data = %+v", data)
					}
					events = append(events, "after-remove-team-member")
					return nil
				},
			},
		})}
	})
	ownerCookies := signUp(t, a, "team-hook-owner@example.com")
	_ = signUp(t, a, "team-hook-target@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Team Hook Org",
		"slug": "team-hook-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create-team", map[string]any{
		"organizationId": org.ID,
		"name":           "Explicit Team",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create explicit team status = %d body=%s", resp.StatusCode, data)
	}
	var team types.Team
	if err := json.Unmarshal(data, &team); err != nil {
		t.Fatalf("decode explicit team: %v", err)
	}
	if team.Name != "Explicit Hook Team" {
		t.Fatalf("created team name = %q", team.Name)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/update-team", map[string]any{
		"teamId": team.ID,
		"data": map[string]any{
			"organizationId": org.ID,
			"name":           "Ignored Team",
		},
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update team status = %d body=%s", resp.StatusCode, data)
	}
	if err := json.Unmarshal(data, &team); err != nil {
		t.Fatalf("decode updated team: %v", err)
	}
	if team.Name != "Updated Hook Team" {
		t.Fatalf("updated team name = %q", team.Name)
	}

	targetUser, err := a.Store().FindUserByEmail(context.Background(), "team-hook-target@example.com")
	if err != nil {
		t.Fatalf("find target user: %v", err)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/add-member", map[string]any{
		"organizationId": org.ID,
		"userId":         targetUser.ID,
		"role":           "member",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add organization member status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/add-team-member", map[string]any{
		"organizationId": org.ID,
		"teamId":         team.ID,
		"userId":         targetUser.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add team member status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/remove-team-member", map[string]any{
		"organizationId": org.ID,
		"teamId":         team.ID,
		"userId":         targetUser.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("remove team member status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/remove-team", map[string]any{
		"organizationId": org.ID,
		"teamId":         team.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("remove team status = %d body=%s", resp.StatusCode, data)
	}

	wantEvents := []string{
		"before-create-team:Team Hook Org",
		"after-create-team:Default Hook Team",
		"before-create-team:Explicit Team",
		"after-create-team:Explicit Hook Team",
		"before-update-team",
		"after-update-team",
		"before-add-team-member",
		"after-add-team-member",
		"before-remove-team-member",
		"after-remove-team-member",
		"before-delete-team",
		"after-delete-team",
	}
	if len(events) != len(wantEvents) {
		t.Fatalf("team hook events = %+v, want %+v", events, wantEvents)
	}
	for i, want := range wantEvents {
		if events[i] != want {
			t.Fatalf("team hook events = %+v, want %+v", events, wantEvents)
		}
	}
}

func TestOrganizationActiveMemberRoutesRequireActiveOrganization(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{})}
	})
	cookies := signUp(t, a, "active-none@example.com")

	resp, data := doRequest(a, http.MethodGet, "/organization/get-active-member", nil, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("get active member without org status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodGet, "/organization/get-active-member-role", nil, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("get active member role without org status = %d body=%s", resp.StatusCode, data)
	}
}

func TestOrganizationGetActiveMemberRoleSupportsQueryOptions(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{})}
	})
	ownerCookies := signUp(t, a, "role-owner@example.com")
	outsiderCookies := signUp(t, a, "role-outsider@example.com")
	_ = signUp(t, a, "role-member@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Role Org",
		"slug": "role-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	memberUser, err := a.Store().FindUserByEmail(context.Background(), "role-member@example.com")
	if err != nil {
		t.Fatalf("find member user: %v", err)
	}
	st := a.Store().(*memory.Store)
	member := types.Member{
		ID:             "role-member",
		OrganizationID: org.ID,
		UserID:         memberUser.ID,
		Role:           "admin",
		CreatedAt:      time.Now(),
	}
	if err := st.CreateMember(context.Background(), &member); err != nil {
		t.Fatalf("create member: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/set-active", map[string]any{
		"organizationId": org.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set active organization status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/get-active-member", nil, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get active member status = %d body=%s", resp.StatusCode, data)
	}
	var active types.Member
	if err := json.Unmarshal(data, &active); err != nil {
		t.Fatalf("decode active member: %v", err)
	}
	if active.Role != "owner" {
		t.Fatalf("active role = %q, want owner", active.Role)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/get-active-member-role?organizationSlug=role-org&userId="+memberUser.ID, nil, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get target member role status = %d body=%s", resp.StatusCode, data)
	}
	var role struct {
		Role string `json:"role"`
	}
	if err := json.Unmarshal(data, &role); err != nil {
		t.Fatalf("decode target role: %v", err)
	}
	if role.Role != "admin" {
		t.Fatalf("target role = %q, want admin", role.Role)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/get-active-member-role?organizationId="+org.ID, nil, outsiderCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("outsider active member role status = %d body=%s", resp.StatusCode, data)
	}
}

func TestOrganizationCreateRespectsExplicitCreationDisabledOption(t *testing.T) {
	allowCreation := false
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			AllowUserToCreateOrganization: &allowCreation,
		})}
	})
	cookies := signUp(t, a, "disabled-create@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Disabled Org",
		"slug": "disabled-org",
	}, cookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("disabled create organization status = %d body=%s", resp.StatusCode, data)
	}
	st := a.Store().(*memory.Store)
	if _, err := st.FindOrganizationBySlug(context.Background(), "disabled-org"); err == nil {
		t.Fatalf("disabled organization creation persisted organization")
	}
}

func TestOrganizationCreateUsesConfiguredCreatorRole(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			CreatorRole: "founder",
		})}
	})
	cookies := signUp(t, a, "creator-role@example.com")
	_ = signUp(t, a, "creator-role-target@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Creator Role Org",
		"slug": "creator-role-org",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var created struct {
		ID      string         `json:"id"`
		Members []types.Member `json:"members"`
	}
	if err := json.Unmarshal(data, &created); err != nil {
		t.Fatalf("decode created organization: %v", err)
	}
	if len(created.Members) != 1 || created.Members[0].Role != "founder" {
		t.Fatalf("creator member role = %+v, want founder", created.Members)
	}
	user, err := a.Store().FindUserByEmail(context.Background(), "creator-role@example.com")
	if err != nil {
		t.Fatalf("find creator user: %v", err)
	}
	st := a.Store().(*memory.Store)
	member, err := st.FindMemberByOrgAndUser(context.Background(), created.ID, user.ID)
	if err != nil {
		t.Fatalf("find creator member: %v", err)
	}
	if member.Role != "founder" {
		t.Fatalf("persisted creator role = %q, want founder", member.Role)
	}
	target, err := a.Store().FindUserByEmail(context.Background(), "creator-role-target@example.com")
	if err != nil {
		t.Fatalf("find creator role target: %v", err)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/add-member", map[string]any{
		"organizationId": created.ID,
		"userId":         target.ID,
		"role":           "member",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add creator role target status = %d body=%s", resp.StatusCode, data)
	}
	var targetMember types.Member
	if err := json.Unmarshal(data, &targetMember); err != nil {
		t.Fatalf("decode creator role target member: %v", err)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/update-member-role", map[string]any{
		"organizationId": created.ID,
		"memberId":       targetMember.ID,
		"role":           "admin",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("creator role update member status = %d body=%s", resp.StatusCode, data)
	}
}

func TestOrganizationCreateCreatesDefaultTeamWhenTeamsEnabled(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{organizationWithTeamsPlugin()}
	})
	cookies := signUp(t, a, "default-team@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Default Team Org",
		"slug": "default-team-org",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var created struct {
		ID      string         `json:"id"`
		Name    string         `json:"name"`
		Members []types.Member `json:"members"`
	}
	if err := json.Unmarshal(data, &created); err != nil {
		t.Fatalf("decode created organization: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("decode raw created organization: %v", err)
	}
	if _, exists := raw["teams"]; exists {
		t.Fatal("create organization response should not include teams")
	}
	if _, exists := raw["invitations"]; exists {
		t.Fatal("create organization response should not include invitations")
	}

	st := a.Store().(*memory.Store)
	user, err := a.Store().FindUserByEmail(context.Background(), "default-team@example.com")
	if err != nil {
		t.Fatalf("find creator user: %v", err)
	}
	teams, err := st.ListTeamsByOrg(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("list default teams: %v", err)
	}
	if len(teams) != 1 || teams[0].Name != created.Name {
		t.Fatalf("default teams = %+v, want one named %q", teams, created.Name)
	}
	if _, err := st.FindTeamMember(context.Background(), teams[0].ID, user.ID); err != nil {
		t.Fatalf("find default team member: %v", err)
	}

	resp, data = doRequest(a, http.MethodGet, "/get-session?disableCookieCache=true", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get session status = %d body=%s", resp.StatusCode, data)
	}
	var session struct {
		Session map[string]any `json:"session"`
	}
	if err := json.Unmarshal(data, &session); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if session.Session[constants.SessionActiveOrganizationID] != created.ID {
		t.Fatalf("active organization = %+v, want %s", session.Session, created.ID)
	}
	if session.Session[constants.SessionActiveTeamID] != teams[0].ID {
		t.Fatalf("active team = %+v, want %s", session.Session, teams[0].ID)
	}
}

func TestOrganizationCreateUsesCustomDefaultTeamCreator(t *testing.T) {
	st := memory.New()
	createDefaultTeam := true
	customTeamID := "custom-default-team-id"
	customTeamName := "Custom Default Team"
	a := newTestAuth(func(c *auth.Config) {
		c.Store = st
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			Teams: &plugins.OrganizationTeamsOptions{
				Enabled: true,
				DefaultTeam: &plugins.OrganizationDefaultTeamOptions{
					Enabled: &createDefaultTeam,
					CustomCreateDefaultTeam: func(ctx context.Context, org types.Organization, user types.User) (*types.Team, error) {
						team := &types.Team{
							ID:             customTeamID,
							Name:           customTeamName,
							OrganizationID: org.ID,
							CreatedAt:      time.Now(),
						}
						if err := st.CreateTeam(ctx, team); err != nil {
							return nil, err
						}
						return team, nil
					},
				},
			},
		})}
	})
	cookies := signUp(t, a, "custom-default-team@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Custom Default Team Org",
		"slug": "custom-default-team-org",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var created types.Organization
	if err := json.Unmarshal(data, &created); err != nil {
		t.Fatalf("decode created organization: %v", err)
	}
	user, err := a.Store().FindUserByEmail(context.Background(), "custom-default-team@example.com")
	if err != nil {
		t.Fatalf("find custom default team user: %v", err)
	}
	teams, err := st.ListTeamsByOrg(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("list custom default teams: %v", err)
	}
	if len(teams) != 1 || teams[0].ID != customTeamID || teams[0].Name != customTeamName {
		t.Fatalf("custom default teams = %+v, want custom team", teams)
	}
	if _, err := st.FindTeamMember(context.Background(), customTeamID, user.ID); err != nil {
		t.Fatalf("find custom default team member: %v", err)
	}

	resp, data = doRequest(a, http.MethodGet, "/get-session?disableCookieCache=true", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get session status = %d body=%s", resp.StatusCode, data)
	}
	var session struct {
		Session map[string]any `json:"session"`
	}
	if err := json.Unmarshal(data, &session); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if session.Session[constants.SessionActiveTeamID] != customTeamID {
		t.Fatalf("active team = %+v, want %s", session.Session, customTeamID)
	}
}

func TestOrganizationCreateSkipsDefaultTeamWhenDisabled(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{organizationWithTeamsDefaultDisabledPlugin()}
	})
	cookies := signUp(t, a, "default-team-disabled@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "No Default Team Org",
		"slug": "no-default-team-org",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &created); err != nil {
		t.Fatalf("decode created organization: %v", err)
	}
	st := a.Store().(*memory.Store)
	teams, err := st.ListTeamsByOrg(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("list default teams: %v", err)
	}
	if len(teams) != 0 {
		t.Fatalf("default teams = %+v, want none", teams)
	}

	resp, data = doRequest(a, http.MethodGet, "/get-session?disableCookieCache=true", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get session status = %d body=%s", resp.StatusCode, data)
	}
	var session struct {
		Session map[string]any `json:"session"`
	}
	if err := json.Unmarshal(data, &session); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if _, exists := session.Session[constants.SessionActiveTeamID]; exists {
		t.Fatalf("active team should not be set: %+v", session.Session)
	}
}

func TestOrganizationCreateTeamRespectsMaximumTeams(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{organizationWithTeamsMaximumPlugin(1)}
	})
	cookies := signUp(t, a, "maximum-teams@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Maximum Teams Org",
		"slug": "maximum-teams-org",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create-team", map[string]any{
		"organizationId": org.ID,
		"name":           "Only Team",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create first team status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/create-team", map[string]any{
		"organizationId": org.ID,
		"name":           "Extra Team",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("create team beyond maximum status = %d body=%s", resp.StatusCode, data)
	}
	st := a.Store().(*memory.Store)
	teams, err := st.ListTeamsByOrg(context.Background(), org.ID)
	if err != nil {
		t.Fatalf("list teams: %v", err)
	}
	if len(teams) != 1 {
		t.Fatalf("teams length = %d, want 1", len(teams))
	}
}

func TestOrganizationAddMemberRespectsMaximumMembersPerTeam(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{organizationWithTeamsMemberLimitPlugin(1)}
	})
	ownerCookies := signUp(t, a, "add-member-team-limit-owner@example.com")
	_ = signUp(t, a, "add-member-team-limit-one@example.com")
	_ = signUp(t, a, "add-member-team-limit-two@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Add Member Team Limit Org",
		"slug": "add-member-team-limit-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create-team", map[string]any{
		"organizationId": org.ID,
		"name":           "Limited Team",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create team status = %d body=%s", resp.StatusCode, data)
	}
	var team types.Team
	if err := json.Unmarshal(data, &team); err != nil {
		t.Fatalf("decode team: %v", err)
	}

	first, err := a.Store().FindUserByEmail(context.Background(), "add-member-team-limit-one@example.com")
	if err != nil {
		t.Fatalf("find first target: %v", err)
	}
	second, err := a.Store().FindUserByEmail(context.Background(), "add-member-team-limit-two@example.com")
	if err != nil {
		t.Fatalf("find second target: %v", err)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/add-member", map[string]any{
		"organizationId": org.ID,
		"userId":         first.ID,
		"role":           "member",
		"teamId":         team.ID,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add first member status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/add-member", map[string]any{
		"organizationId": org.ID,
		"userId":         second.ID,
		"role":           "member",
		"teamId":         team.ID,
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("add member beyond team limit status = %d body=%s", resp.StatusCode, data)
	}
	st := a.Store().(*memory.Store)
	if _, err := st.FindMemberByOrgAndUser(context.Background(), org.ID, second.ID); err == nil {
		t.Fatal("team-limited add-member persisted organization member")
	}
}

func TestOrganizationAddTeamMemberRespectsMaximumMembersPerTeam(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{organizationWithTeamsMemberLimitPlugin(1)}
	})
	ownerCookies := signUp(t, a, "add-team-member-limit-owner@example.com")
	_ = signUp(t, a, "add-team-member-limit-target@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Add Team Member Limit Org",
		"slug": "add-team-member-limit-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create-team", map[string]any{
		"organizationId": org.ID,
		"name":           "Limited Team",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create team status = %d body=%s", resp.StatusCode, data)
	}
	var team types.Team
	if err := json.Unmarshal(data, &team); err != nil {
		t.Fatalf("decode team: %v", err)
	}

	owner, err := a.Store().FindUserByEmail(context.Background(), "add-team-member-limit-owner@example.com")
	if err != nil {
		t.Fatalf("find owner: %v", err)
	}
	target, err := a.Store().FindUserByEmail(context.Background(), "add-team-member-limit-target@example.com")
	if err != nil {
		t.Fatalf("find target: %v", err)
	}
	st := a.Store().(*memory.Store)
	if err := st.CreateMember(context.Background(), &types.Member{
		ID:             "team-limit-target-member",
		OrganizationID: org.ID,
		UserID:         target.ID,
		Role:           "member",
		CreatedAt:      time.Now(),
	}); err != nil {
		t.Fatalf("create target member: %v", err)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/add-team-member", map[string]any{
		"organizationId": org.ID,
		"teamId":         team.ID,
		"userId":         owner.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add owner team member status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/add-team-member", map[string]any{
		"organizationId": org.ID,
		"teamId":         team.ID,
		"userId":         target.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("add team member beyond limit status = %d body=%s", resp.StatusCode, data)
	}
	if _, err := st.FindTeamMember(context.Background(), team.ID, target.ID); err == nil {
		t.Fatal("team-limited add-team-member persisted team member")
	}
}

func TestOrganizationRemoveTeamAllowsRemovingLastTeamWhenConfigured(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{organizationWithRemovableTeamsPlugin()}
	})
	cookies := signUp(t, a, "remove-all-teams@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Remove All Teams Org",
		"slug": "remove-all-teams-org",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create-team", map[string]any{
		"organizationId": org.ID,
		"name":           "Temporary Team",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create team status = %d body=%s", resp.StatusCode, data)
	}
	var team types.Team
	if err := json.Unmarshal(data, &team); err != nil {
		t.Fatalf("decode team: %v", err)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/remove-team", map[string]any{
		"organizationId": org.ID,
		"teamId":         team.ID,
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("remove only team status = %d body=%s", resp.StatusCode, data)
	}
	st := a.Store().(*memory.Store)
	teams, err := st.ListTeamsByOrg(context.Background(), org.ID)
	if err != nil {
		t.Fatalf("list teams: %v", err)
	}
	if len(teams) != 0 {
		t.Fatalf("teams length = %d, want 0", len(teams))
	}
}

func TestOrganizationCreateRespectsOrganizationLimit(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			OrganizationLimit: 1,
		})}
	})
	cookies := signUp(t, a, "org-limit@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "First Limited Org",
		"slug": "first-limited-org",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first create organization status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Second Limited Org",
		"slug": "second-limited-org",
	}, cookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("limited create organization status = %d body=%s", resp.StatusCode, data)
	}

	st := a.Store().(*memory.Store)
	if _, err := st.FindOrganizationBySlug(context.Background(), "second-limited-org"); err == nil {
		t.Fatalf("limited organization creation persisted organization")
	}
	user, err := a.Store().FindUserByEmail(context.Background(), "org-limit@example.com")
	if err != nil {
		t.Fatalf("find limited user: %v", err)
	}
	members, err := st.ListMembersByUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("list limited user memberships: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("limited user memberships = %d, want 1", len(members))
	}
}

func TestOrganizationAddMemberServerOnlyRouteCreatesMember(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{organizationWithTeamsPlugin()}
	})
	ownerCookies := signUp(t, a, "add-member-owner@example.com")
	_ = signUp(t, a, "add-member-target@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Add Member Org",
		"slug": "add-member-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create add-member organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode add-member organization: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create-team", map[string]any{
		"organizationId": org.ID,
		"name":           "Add Member Team",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create add-member team status = %d body=%s", resp.StatusCode, data)
	}
	var team types.Team
	if err := json.Unmarshal(data, &team); err != nil {
		t.Fatalf("decode add-member team: %v", err)
	}

	target, err := a.Store().FindUserByEmail(context.Background(), "add-member-target@example.com")
	if err != nil {
		t.Fatalf("find add-member target: %v", err)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/add-member", map[string]any{
		"organizationId": org.ID,
		"userId":         target.ID,
		"role":           []string{"member", "admin"},
		"teamId":         team.ID,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add member status = %d body=%s", resp.StatusCode, data)
	}
	var member types.Member
	if err := json.Unmarshal(data, &member); err != nil {
		t.Fatalf("decode added organization member: %v", err)
	}
	if member.OrganizationID != org.ID || member.UserID != target.ID || member.Role != "member,admin" {
		t.Fatalf("added member = %+v", member)
	}
	st := a.Store().(*memory.Store)
	if _, err := st.FindMemberByOrgAndUser(context.Background(), org.ID, target.ID); err != nil {
		t.Fatalf("find added member: %v", err)
	}
	if _, err := st.FindTeamMember(context.Background(), team.ID, target.ID); err != nil {
		t.Fatalf("find added team member: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/add-member", map[string]any{
		"organizationId": org.ID,
		"userId":         target.ID,
		"role":           "member",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("duplicate add member status = %d body=%s", resp.StatusCode, data)
	}
}

func TestOrganizationUsesDynamicLimitCallbacks(t *testing.T) {
	defaultTeamEnabled := false
	organizationLimitCalls := 0
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			AllowUserToCreateOrganizationFunc: func(ctx context.Context, user types.User) (bool, error) {
				return user.Email != "dynamic-callback-denied@example.com", nil
			},
			OrganizationLimitReached: func(ctx context.Context, user types.User) (bool, error) {
				organizationLimitCalls++
				return organizationLimitCalls > 1, nil
			},
			MembershipLimitFunc: func(ctx context.Context, user types.User, org types.Organization) (int, error) {
				return 3, nil
			},
			InvitationLimitFunc: func(ctx context.Context, data plugins.OrganizationInvitationLimitData) (int, error) {
				return 1, nil
			},
			DynamicAccessControl: &plugins.OrganizationDynamicAccessControlOptions{
				Enabled: true,
				MaximumRolesPerOrganizationFunc: func(ctx context.Context, organizationID string) (int, error) {
					return 1, nil
				},
			},
			Teams: &plugins.OrganizationTeamsOptions{
				Enabled: true,
				DefaultTeam: &plugins.OrganizationDefaultTeamOptions{
					Enabled: &defaultTeamEnabled,
				},
				MaximumTeamsFunc: func(ctx context.Context, data plugins.OrganizationMaximumTeamsData) (int, error) {
					if data.OrganizationID == "" || data.Session == nil || data.User == nil {
						t.Fatalf("maximum teams data = %+v, want organization, session, and user", data)
					}
					return 1, nil
				},
				MaximumMembersPerTeamFunc: func(ctx context.Context, data plugins.OrganizationMaximumMembersPerTeamData) (int, error) {
					if data.TeamID == "" || data.OrganizationID == "" || data.Session == nil || data.User == nil {
						t.Fatalf("maximum members data = %+v, want team, organization, session, and user", data)
					}
					return 1, nil
				},
			},
		})}
	})
	deniedCookies := signUp(t, a, "dynamic-callback-denied@example.com")
	ownerCookies := signUp(t, a, "dynamic-callback-owner@example.com")
	_ = signUp(t, a, "dynamic-callback-target-one@example.com")
	_ = signUp(t, a, "dynamic-callback-target-two@example.com")
	_ = signUp(t, a, "dynamic-callback-target-three@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Denied Dynamic Org",
		"slug": "denied-dynamic-org",
	}, deniedCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied dynamic create status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Dynamic Callback Org",
		"slug": "dynamic-callback-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create dynamic callback organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode dynamic callback organization: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Second Dynamic Callback Org",
		"slug": "second-dynamic-callback-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("dynamic organization limit status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "dynamic-callback-invite-one@example.com",
		"role":           "member",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first dynamic invitation status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "dynamic-callback-invite-two@example.com",
		"role":           "member",
	}, ownerCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("dynamic invitation limit status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create-role", map[string]any{
		"organizationId": org.ID,
		"role":           "Reviewer",
		"permission":     map[string][]string{"organization": []string{"update"}},
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first dynamic role status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/create-role", map[string]any{
		"organizationId": org.ID,
		"role":           "Publisher",
		"permission":     map[string][]string{"organization": []string{"update"}},
	}, ownerCookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("dynamic role limit status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create-team", map[string]any{
		"organizationId": org.ID,
		"name":           "Only Dynamic Team",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first dynamic team status = %d body=%s", resp.StatusCode, data)
	}
	var team types.Team
	if err := json.Unmarshal(data, &team); err != nil {
		t.Fatalf("decode dynamic team: %v", err)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/create-team", map[string]any{
		"organizationId": org.ID,
		"name":           "Extra Dynamic Team",
	}, ownerCookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("dynamic team limit status = %d body=%s", resp.StatusCode, data)
	}

	targetOne, err := a.Store().FindUserByEmail(context.Background(), "dynamic-callback-target-one@example.com")
	if err != nil {
		t.Fatalf("find first dynamic target: %v", err)
	}
	targetTwo, err := a.Store().FindUserByEmail(context.Background(), "dynamic-callback-target-two@example.com")
	if err != nil {
		t.Fatalf("find second dynamic target: %v", err)
	}
	targetThree, err := a.Store().FindUserByEmail(context.Background(), "dynamic-callback-target-three@example.com")
	if err != nil {
		t.Fatalf("find third dynamic target: %v", err)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/add-member", map[string]any{
		"organizationId": org.ID,
		"userId":         targetOne.ID,
		"role":           "member",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first dynamic add member status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/add-member", map[string]any{
		"organizationId": org.ID,
		"userId":         targetTwo.ID,
		"role":           "member",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second dynamic add member status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/add-member", map[string]any{
		"organizationId": org.ID,
		"userId":         targetThree.ID,
		"role":           "member",
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("dynamic membership limit status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/add-team-member", map[string]any{
		"organizationId": org.ID,
		"teamId":         team.ID,
		"userId":         targetOne.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first dynamic team member status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/add-team-member", map[string]any{
		"organizationId": org.ID,
		"teamId":         team.ID,
		"userId":         targetTwo.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("dynamic team member limit status = %d body=%s", resp.StatusCode, data)
	}
}

func TestOrganizationAddMemberWithDynamicTeamLimitRequiresSession(t *testing.T) {
	defaultTeamEnabled := false
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			Teams: &plugins.OrganizationTeamsOptions{
				Enabled: true,
				DefaultTeam: &plugins.OrganizationDefaultTeamOptions{
					Enabled: &defaultTeamEnabled,
				},
				MaximumMembersPerTeamFunc: func(ctx context.Context, data plugins.OrganizationMaximumMembersPerTeamData) (int, error) {
					if data.Session == nil || data.User == nil {
						t.Fatalf("maximum members callback missing session data: %+v", data)
					}
					return 2, nil
				},
			},
		})}
	})
	ownerCookies := signUp(t, a, "dynamic-team-session-owner@example.com")
	_ = signUp(t, a, "dynamic-team-session-target@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Dynamic Team Session Org",
		"slug": "dynamic-team-session-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/create-team", map[string]any{
		"organizationId": org.ID,
		"name":           "Session Required Team",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create team status = %d body=%s", resp.StatusCode, data)
	}
	var team types.Team
	if err := json.Unmarshal(data, &team); err != nil {
		t.Fatalf("decode team: %v", err)
	}
	target, err := a.Store().FindUserByEmail(context.Background(), "dynamic-team-session-target@example.com")
	if err != nil {
		t.Fatalf("find target: %v", err)
	}

	body := map[string]any{
		"organizationId": org.ID,
		"teamId":         team.ID,
		"userId":         target.ID,
		"role":           "member",
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/add-member", body, nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("sessionless dynamic team add status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/add-member", body, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session-backed dynamic team add status = %d body=%s", resp.StatusCode, data)
	}
}

func TestOrganizationAddMemberRespectsMembershipLimit(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			MembershipLimit: 1,
		})}
	})
	ownerCookies := signUp(t, a, "add-member-limit-owner@example.com")
	_ = signUp(t, a, "add-member-limit-target@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Add Member Limit Org",
		"slug": "add-member-limit-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create add-member limit organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode add-member limit organization: %v", err)
	}
	target, err := a.Store().FindUserByEmail(context.Background(), "add-member-limit-target@example.com")
	if err != nil {
		t.Fatalf("find add-member limit target: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/add-member", map[string]any{
		"organizationId": org.ID,
		"userId":         target.ID,
		"role":           "member",
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("limited add member status = %d body=%s", resp.StatusCode, data)
	}
	st := a.Store().(*memory.Store)
	if _, err := st.FindMemberByOrgAndUser(context.Background(), org.ID, target.ID); err == nil {
		t.Fatalf("limited add member persisted member")
	}
}

func TestOrganizationTeamRoutesPersistAndValidateMembership(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{organizationWithTeamsPlugin()}
	})
	ownerCookies := signUp(t, a, "team-owner@example.com")
	memberCookies := signUp(t, a, "team-member@example.com")
	outsiderCookies := signUp(t, a, "team-outsider@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Team Org",
		"slug": "team-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create-team", map[string]any{
		"organizationId": org.ID,
		"name":           "Engineering",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create team status = %d body=%s", resp.StatusCode, data)
	}
	var team types.Team
	if err := json.Unmarshal(data, &team); err != nil {
		t.Fatalf("decode team: %v", err)
	}
	if team.Name != "Engineering" || team.OrganizationID != org.ID {
		t.Fatalf("created team = %+v", team)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create-team", map[string]any{
		"organizationId": org.ID,
		"name":           "Support",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create second team status = %d body=%s", resp.StatusCode, data)
	}
	var secondTeam types.Team
	if err := json.Unmarshal(data, &secondTeam); err != nil {
		t.Fatalf("decode second team: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/update-team", map[string]any{
		"teamId": team.ID,
		"data": map[string]any{
			"organizationId": org.ID,
			"name":           "Platform",
		},
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update team status = %d body=%s", resp.StatusCode, data)
	}
	var updated types.Team
	if err := json.Unmarshal(data, &updated); err != nil {
		t.Fatalf("decode updated team: %v", err)
	}
	if updated.Name != "Platform" {
		t.Fatalf("updated team name = %q, want Platform", updated.Name)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/list-teams?organizationId="+org.ID, nil, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list teams status = %d body=%s", resp.StatusCode, data)
	}
	var teams []types.Team
	if err := json.Unmarshal(data, &teams); err != nil {
		t.Fatalf("decode teams: %v", err)
	}
	if len(teams) != 3 {
		t.Fatalf("teams length = %d, want 3", len(teams))
	}
	var defaultTeamID string
	for _, listedTeam := range teams {
		if listedTeam.Name == org.Name {
			defaultTeamID = listedTeam.ID
			break
		}
	}
	if defaultTeamID == "" {
		t.Fatalf("default team not found in teams: %+v", teams)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/list-teams?organizationId="+org.ID, nil, outsiderCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("outsider list teams status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/remove-team", map[string]any{
		"organizationId": org.ID,
		"teamId":         team.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("remove team status = %d body=%s", resp.StatusCode, data)
	}
	var removed struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(data, &removed); err != nil {
		t.Fatalf("decode removed team response: %v", err)
	}
	if removed.Message != "Team removed successfully." {
		t.Fatalf("remove message = %q", removed.Message)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/remove-team", map[string]any{
		"organizationId": org.ID,
		"teamId":         defaultTeamID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("remove active default team status = %d body=%s", resp.StatusCode, data)
	}

	st := a.Store().(*memory.Store)
	memberUser, err := a.Store().FindUserByEmail(context.Background(), "team-member@example.com")
	if err != nil {
		t.Fatalf("find team member user: %v", err)
	}
	if err := st.CreateMember(context.Background(), &types.Member{
		ID:             "team-org-member",
		OrganizationID: org.ID,
		UserID:         memberUser.ID,
		Role:           "member",
		CreatedAt:      time.Now(),
	}); err != nil {
		t.Fatalf("create organization member: %v", err)
	}
	if err := st.CreateTeamMember(context.Background(), &types.TeamMember{
		ID: "team-membership", TeamID: secondTeam.ID, UserID: memberUser.ID, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create team member: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/set-active", map[string]any{
		"organizationId": org.ID,
	}, memberCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set active organization status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/set-active-team", map[string]any{
		"teamId": secondTeam.ID,
	}, memberCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set active team status = %d body=%s", resp.StatusCode, data)
	}
	var activeTeam types.Team
	if err := json.Unmarshal(data, &activeTeam); err != nil {
		t.Fatalf("decode active team: %v", err)
	}
	if activeTeam.ID != secondTeam.ID {
		t.Fatalf("active team id = %q, want %q", activeTeam.ID, secondTeam.ID)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/list-user-teams", nil, memberCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list user teams status = %d body=%s", resp.StatusCode, data)
	}
	if err := json.Unmarshal(data, &teams); err != nil {
		t.Fatalf("decode user teams: %v", err)
	}
	if len(teams) != 1 || teams[0].ID != secondTeam.ID {
		t.Fatalf("user teams = %+v, want only %s", teams, secondTeam.ID)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/list-team-members", nil, memberCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list active team members status = %d body=%s", resp.StatusCode, data)
	}
	var teamMembers []types.TeamMember
	if err := json.Unmarshal(data, &teamMembers); err != nil {
		t.Fatalf("decode active team members: %v", err)
	}
	if len(teamMembers) != 1 || teamMembers[0].UserID != memberUser.ID {
		t.Fatalf("active team members = %+v, want member %s", teamMembers, memberUser.ID)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/list-team-members?teamId="+secondTeam.ID, nil, outsiderCookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("outsider list team members status = %d body=%s", resp.StatusCode, data)
	}

	ownerUser, err := a.Store().FindUserByEmail(context.Background(), "team-owner@example.com")
	if err != nil {
		t.Fatalf("find team owner user: %v", err)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/add-team-member", map[string]any{
		"organizationId": org.ID,
		"teamId":         secondTeam.ID,
		"userId":         ownerUser.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add team member status = %d body=%s", resp.StatusCode, data)
	}
	var added types.TeamMember
	if err := json.Unmarshal(data, &added); err != nil {
		t.Fatalf("decode added team member: %v", err)
	}
	if added.TeamID != secondTeam.ID || added.UserID != ownerUser.ID {
		t.Fatalf("added team member = %+v", added)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/add-team-member", map[string]any{
		"organizationId": org.ID,
		"teamId":         secondTeam.ID,
		"userId":         ownerUser.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add existing team member status = %d body=%s", resp.StatusCode, data)
	}
	var existing types.TeamMember
	if err := json.Unmarshal(data, &existing); err != nil {
		t.Fatalf("decode existing team member: %v", err)
	}
	if existing.ID != added.ID {
		t.Fatalf("existing team member id = %q, want %q", existing.ID, added.ID)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/remove-team-member", map[string]any{
		"organizationId": org.ID,
		"teamId":         secondTeam.ID,
		"userId":         ownerUser.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("remove team member status = %d body=%s", resp.StatusCode, data)
	}
	var removedTeamMember struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(data, &removedTeamMember); err != nil {
		t.Fatalf("decode removed team member response: %v", err)
	}
	if removedTeamMember.Message != "Team member removed successfully." {
		t.Fatalf("remove team member message = %q", removedTeamMember.Message)
	}
	if _, err := st.FindTeamMember(context.Background(), secondTeam.ID, ownerUser.ID); err == nil {
		t.Fatal("expected owner team membership to be removed")
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/remove-team-member", map[string]any{
		"organizationId": org.ID,
		"teamId":         secondTeam.ID,
		"userId":         memberUser.ID,
	}, memberCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member remove team member status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/set-active-team", map[string]any{
		"teamId": nil,
	}, memberCookies)
	if resp.StatusCode != http.StatusOK || string(data) != "null" {
		t.Fatalf("clear active team status = %d body=%s", resp.StatusCode, data)
	}
}

func TestOrganizationInvitationCreateAndAcceptPersistsMemberships(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{organizationWithTeamsPlugin()}
	})
	ownerCookies := signUp(t, a, "invite-owner@example.com")
	inviteeCookies := signUp(t, a, "invitee@example.com")
	outsiderCookies := signUp(t, a, "invite-outsider@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Invite Org",
		"slug": "invite-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create-team", map[string]any{
		"organizationId": org.ID,
		"name":           "Invited Team",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create team status = %d body=%s", resp.StatusCode, data)
	}
	var team types.Team
	if err := json.Unmarshal(data, &team); err != nil {
		t.Fatalf("decode team: %v", err)
	}

	beforeInvite := time.Now()
	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "invitee@example.com",
		"role":           []string{"member", "admin"},
		"teamId":         team.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invite member status = %d body=%s", resp.StatusCode, data)
	}
	var invitation types.Invitation
	if err := json.Unmarshal(data, &invitation); err != nil {
		t.Fatalf("decode invitation: %v", err)
	}
	if invitation.Email != "invitee@example.com" || invitation.Status != "pending" || invitation.TeamID != team.ID {
		t.Fatalf("invitation = %+v", invitation)
	}
	if invitation.Role != "member,admin" {
		t.Fatalf("invitation role = %q, want member,admin", invitation.Role)
	}
	if invitation.ExpiresAt.Before(beforeInvite.Add(47*time.Hour)) || invitation.ExpiresAt.After(beforeInvite.Add(49*time.Hour)) {
		t.Fatalf("invitation expiry = %s, want about 48h from %s", invitation.ExpiresAt, beforeInvite)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "invitee@example.com",
		"role":           "member",
	}, ownerCookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("duplicate invite status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/accept-invitation", map[string]any{
		"invitationId": invitation.ID,
	}, outsiderCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong recipient accept status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/accept-invitation", map[string]any{
		"invitationId": invitation.ID,
	}, inviteeCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("accept invitation status = %d body=%s", resp.StatusCode, data)
	}
	var accepted struct {
		Invitation types.Invitation `json:"invitation"`
		Member     types.Member     `json:"member"`
	}
	if err := json.Unmarshal(data, &accepted); err != nil {
		t.Fatalf("decode accepted invitation: %v", err)
	}
	if accepted.Invitation.Status != "accepted" || accepted.Member.OrganizationID != org.ID || accepted.Member.Role != "member,admin" {
		t.Fatalf("accepted response = %+v", accepted)
	}

	st := a.Store().(*memory.Store)
	invitee, err := a.Store().FindUserByEmail(context.Background(), "invitee@example.com")
	if err != nil {
		t.Fatalf("find invitee: %v", err)
	}
	member, err := st.FindMemberByOrgAndUser(context.Background(), org.ID, invitee.ID)
	if err != nil {
		t.Fatalf("find accepted member: %v", err)
	}
	if member.Role != "member,admin" {
		t.Fatalf("persisted member role = %q, want member,admin", member.Role)
	}
	if _, err := st.FindTeamMember(context.Background(), team.ID, invitee.ID); err != nil {
		t.Fatalf("find accepted team member: %v", err)
	}
	persistedInvitation, err := st.FindInvitationByID(context.Background(), invitation.ID)
	if err != nil {
		t.Fatalf("find persisted invitation: %v", err)
	}
	if persistedInvitation.Status != "accepted" {
		t.Fatalf("persisted invitation status = %q, want accepted", persistedInvitation.Status)
	}
}

func TestOrganizationInvitationOptionsControlExpiryResendAndLimit(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			InvitationExpiresIn: 2 * time.Hour,
			InvitationLimit:     1,
		})}
	})
	ownerCookies := signUp(t, a, "invite-options-owner@example.com")
	_ = signUp(t, a, "invite-options-one@example.com")
	_ = signUp(t, a, "invite-options-two@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Invite Options Org",
		"slug": "invite-options-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	beforeInvite := time.Now()
	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "invite-options-one@example.com",
		"role":           "member",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invite member status = %d body=%s", resp.StatusCode, data)
	}
	var invitation types.Invitation
	if err := json.Unmarshal(data, &invitation); err != nil {
		t.Fatalf("decode invitation: %v", err)
	}
	if invitation.ExpiresAt.Before(beforeInvite.Add(119*time.Minute)) || invitation.ExpiresAt.After(beforeInvite.Add(121*time.Minute)) {
		t.Fatalf("invitation expiry = %s, want about 2h from %s", invitation.ExpiresAt, beforeInvite)
	}

	st := a.Store().(*memory.Store)
	oldExpiry := time.Now().Add(time.Minute)
	if err := st.UpdateInvitationExpiresAt(context.Background(), invitation.ID, oldExpiry); err != nil {
		t.Fatalf("shrink invitation expiry: %v", err)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "invite-options-one@example.com",
		"role":           "member",
		"resend":         true,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resend invitation status = %d body=%s", resp.StatusCode, data)
	}
	var resent types.Invitation
	if err := json.Unmarshal(data, &resent); err != nil {
		t.Fatalf("decode resent invitation: %v", err)
	}
	if resent.ID != invitation.ID {
		t.Fatalf("resent invitation id = %q, want %q", resent.ID, invitation.ID)
	}
	if !resent.ExpiresAt.After(oldExpiry.Add(time.Hour)) {
		t.Fatalf("resent expiry = %s, want extended after %s", resent.ExpiresAt, oldExpiry)
	}
	persisted, err := st.FindInvitationByID(context.Background(), invitation.ID)
	if err != nil {
		t.Fatalf("find resent invitation: %v", err)
	}
	if !persisted.ExpiresAt.Equal(resent.ExpiresAt) {
		t.Fatalf("persisted resent expiry = %s, want %s", persisted.ExpiresAt, resent.ExpiresAt)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "invite-options-two@example.com",
		"role":           "member",
	}, ownerCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("invite beyond invitation limit status = %d body=%s", resp.StatusCode, data)
	}
}

func TestOrganizationInvitationCancelPendingOnReInvite(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			CancelPendingInvitationsOnReInvite: true,
		})}
	})
	ownerCookies := signUp(t, a, "invite-cancel-owner@example.com")
	_ = signUp(t, a, "invite-cancel-recipient@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Invite Cancel Org",
		"slug": "invite-cancel-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "invite-cancel-recipient@example.com",
		"role":           "member",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first invite status = %d body=%s", resp.StatusCode, data)
	}
	var first types.Invitation
	if err := json.Unmarshal(data, &first); err != nil {
		t.Fatalf("decode first invitation: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "invite-cancel-recipient@example.com",
		"role":           "admin",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second invite status = %d body=%s", resp.StatusCode, data)
	}
	var second types.Invitation
	if err := json.Unmarshal(data, &second); err != nil {
		t.Fatalf("decode second invitation: %v", err)
	}
	if second.ID == first.ID {
		t.Fatalf("second invitation reused id %q", second.ID)
	}
	st := a.Store().(*memory.Store)
	persistedFirst, err := st.FindInvitationByID(context.Background(), first.ID)
	if err != nil {
		t.Fatalf("find first invitation: %v", err)
	}
	if persistedFirst.Status != constants.InvitationCanceled {
		t.Fatalf("first invitation status = %q, want canceled", persistedFirst.Status)
	}
	if second.Status != constants.InvitationPending || second.Role != constants.RoleAdmin {
		t.Fatalf("second invitation = %+v", second)
	}
}

func TestOrganizationInvitationEmailHookRunsForCreateAndResend(t *testing.T) {
	calls := []plugins.OrganizationInvitationEmailData{}
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			SendInvitationEmail: func(_ context.Context, data plugins.OrganizationInvitationEmailData) error {
				calls = append(calls, data)
				return nil
			},
		})}
	})
	ownerCookies := signUp(t, a, "invite-email-owner@example.com")
	_ = signUp(t, a, "invite-email-recipient@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Invite Email Org",
		"slug": "invite-email-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "invite-email-recipient@example.com",
		"role":           "member",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invite member status = %d body=%s", resp.StatusCode, data)
	}
	var invitation types.Invitation
	if err := json.Unmarshal(data, &invitation); err != nil {
		t.Fatalf("decode invitation: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("email hook calls after create = %d, want 1", len(calls))
	}
	if calls[0].ID != invitation.ID || calls[0].Email != "invite-email-recipient@example.com" || calls[0].Organization.ID != org.ID || calls[0].InviterUser.Email != "invite-email-owner@example.com" || calls[0].Request == nil {
		t.Fatalf("email hook payload after create = %+v", calls[0])
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "invite-email-recipient@example.com",
		"role":           "member",
		"resend":         true,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resend invitation status = %d body=%s", resp.StatusCode, data)
	}
	var resent types.Invitation
	if err := json.Unmarshal(data, &resent); err != nil {
		t.Fatalf("decode resent invitation: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("email hook calls after resend = %d, want 2", len(calls))
	}
	if calls[1].ID != invitation.ID || calls[1].Invitation.ID != resent.ID || !calls[1].Invitation.ExpiresAt.Equal(resent.ExpiresAt) {
		t.Fatalf("email hook payload after resend = %+v, resent=%+v", calls[1], resent)
	}
}

func TestOrganizationInvitationVerificationGateForIdActions(t *testing.T) {
	requireVerification := true
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			RequireEmailVerificationOnInvitation: &requireVerification,
		})}
	})
	ownerCookies := signUp(t, a, "invite-verify-owner@example.com")
	recipientCookies := signUp(t, a, "invite-verify-recipient@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Invite Verify Org",
		"slug": "invite-verify-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "invite-verify-recipient@example.com",
		"role":           "member",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invite member status = %d body=%s", resp.StatusCode, data)
	}
	var invitation types.Invitation
	if err := json.Unmarshal(data, &invitation); err != nil {
		t.Fatalf("decode invitation: %v", err)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/list-user-invitations", nil, recipientCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unverified list user invitations status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodGet, "/organization/get-invitation?id="+invitation.ID, nil, recipientCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unverified get invitation status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/reject-invitation", map[string]any{
		"invitationId": invitation.ID,
	}, recipientCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unverified reject invitation status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/accept-invitation", map[string]any{
		"invitationId": invitation.ID,
	}, recipientCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unverified accept invitation status = %d body=%s", resp.StatusCode, data)
	}

	verifyUserEmail(t, a, "invite-verify-recipient@example.com")
	resp, data = doRequest(a, http.MethodGet, "/organization/list-user-invitations", nil, recipientCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verified list user invitations status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodGet, "/organization/get-invitation?id="+invitation.ID, nil, recipientCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verified get invitation status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/accept-invitation", map[string]any{
		"invitationId": invitation.ID,
	}, recipientCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verified accept invitation status = %d body=%s", resp.StatusCode, data)
	}
}

func TestOrganizationInvitationLifecycleHooks(t *testing.T) {
	events := []string{}
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			OrganizationHooks: &plugins.OrganizationHooks{
				BeforeCreateInvitation: func(_ context.Context, data plugins.OrganizationInvitationCreateHookData) (*plugins.OrganizationInvitationCreateData, error) {
					events = append(events, "before-create:"+data.Invitation.Email)
					updated := data.Invitation
					if data.Invitation.Email == "inv-hook-accept@example.com" {
						updated.Role = constants.RoleAdmin
					}
					return &updated, nil
				},
				AfterCreateInvitation: func(_ context.Context, data plugins.OrganizationInvitationHookData) error {
					events = append(events, "after-create:"+data.Invitation.Email+":"+data.Invitation.Role)
					return nil
				},
				BeforeAcceptInvitation: func(_ context.Context, data plugins.OrganizationInvitationUserHookData) error {
					if data.User.Email != "inv-hook-accept@example.com" || data.Invitation.Role != constants.RoleAdmin {
						t.Fatalf("before accept hook data = %+v", data)
					}
					events = append(events, "before-accept")
					return nil
				},
				AfterAcceptInvitation: func(_ context.Context, data plugins.OrganizationInvitationAcceptHookData) error {
					if data.User.Email != "inv-hook-accept@example.com" || data.Member.Role != constants.RoleAdmin || data.Invitation.Status != constants.InvitationAccepted {
						t.Fatalf("after accept hook data = %+v", data)
					}
					events = append(events, "after-accept")
					return nil
				},
				BeforeRejectInvitation: func(_ context.Context, data plugins.OrganizationInvitationUserHookData) error {
					if data.User.Email != "inv-hook-reject@example.com" {
						t.Fatalf("before reject hook data = %+v", data)
					}
					events = append(events, "before-reject")
					return nil
				},
				AfterRejectInvitation: func(_ context.Context, data plugins.OrganizationInvitationUserHookData) error {
					if data.Invitation.Status != constants.InvitationRejected {
						t.Fatalf("after reject hook data = %+v", data)
					}
					events = append(events, "after-reject")
					return nil
				},
				BeforeCancelInvitation: func(_ context.Context, data plugins.OrganizationInvitationCancelHookData) error {
					if data.CancelledBy.Email != "inv-hook-owner@example.com" {
						t.Fatalf("before cancel hook data = %+v", data)
					}
					events = append(events, "before-cancel")
					return nil
				},
				AfterCancelInvitation: func(_ context.Context, data plugins.OrganizationInvitationCancelHookData) error {
					if data.Invitation.Status != constants.InvitationCanceled {
						t.Fatalf("after cancel hook data = %+v", data)
					}
					events = append(events, "after-cancel")
					return nil
				},
			},
		})}
	})
	ownerCookies := signUp(t, a, "inv-hook-owner@example.com")
	acceptCookies := signUp(t, a, "inv-hook-accept@example.com")
	rejectCookies := signUp(t, a, "inv-hook-reject@example.com")
	_ = signUp(t, a, "inv-hook-cancel@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Invitation Hook Org",
		"slug": "invitation-hook-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	invite := func(email string) types.Invitation {
		t.Helper()
		resp, data := doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
			"organizationId": org.ID,
			"email":          email,
			"role":           "member",
		}, ownerCookies)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("invite %s status = %d body=%s", email, resp.StatusCode, data)
		}
		var invitation types.Invitation
		if err := json.Unmarshal(data, &invitation); err != nil {
			t.Fatalf("decode invitation %s: %v", email, err)
		}
		return invitation
	}
	acceptInvitation := invite("inv-hook-accept@example.com")
	if acceptInvitation.Role != constants.RoleAdmin {
		t.Fatalf("accept invitation role = %q, want admin", acceptInvitation.Role)
	}
	rejectInvitation := invite("inv-hook-reject@example.com")
	cancelInvitation := invite("inv-hook-cancel@example.com")

	resp, data = doRequest(a, http.MethodPost, "/organization/accept-invitation", map[string]any{
		"invitationId": acceptInvitation.ID,
	}, acceptCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("accept invitation status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/reject-invitation", map[string]any{
		"invitationId": rejectInvitation.ID,
	}, rejectCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reject invitation status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/cancel-invitation", map[string]any{
		"invitationId": cancelInvitation.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cancel invitation status = %d body=%s", resp.StatusCode, data)
	}

	wantEvents := []string{
		"before-create:inv-hook-accept@example.com",
		"after-create:inv-hook-accept@example.com:admin",
		"before-create:inv-hook-reject@example.com",
		"after-create:inv-hook-reject@example.com:member",
		"before-create:inv-hook-cancel@example.com",
		"after-create:inv-hook-cancel@example.com:member",
		"before-accept",
		"after-accept",
		"before-reject",
		"after-reject",
		"before-cancel",
		"after-cancel",
	}
	if len(events) != len(wantEvents) {
		t.Fatalf("invitation hook events = %+v, want %+v", events, wantEvents)
	}
	for i, want := range wantEvents {
		if events[i] != want {
			t.Fatalf("invitation hook events = %+v, want %+v", events, wantEvents)
		}
	}
}

func TestOrganizationInvitationRespectsMaximumMembersPerTeam(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{organizationWithTeamsMemberLimitPlugin(1)}
	})
	ownerCookies := signUp(t, a, "invite-team-limit-owner@example.com")
	pendingInviteeCookies := signUp(t, a, "invite-team-limit-pending@example.com")
	_ = signUp(t, a, "invite-team-limit-full@example.com")
	_ = signUp(t, a, "invite-team-limit-rejected@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Invite Team Limit Org",
		"slug": "invite-team-limit-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/create-team", map[string]any{
		"organizationId": org.ID,
		"name":           "Limited Invite Team",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create team status = %d body=%s", resp.StatusCode, data)
	}
	var team types.Team
	if err := json.Unmarshal(data, &team); err != nil {
		t.Fatalf("decode team: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "invite-team-limit-pending@example.com",
		"role":           "member",
		"teamId":         team.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invite before full status = %d body=%s", resp.StatusCode, data)
	}
	var invitation types.Invitation
	if err := json.Unmarshal(data, &invitation); err != nil {
		t.Fatalf("decode invitation: %v", err)
	}

	st := a.Store().(*memory.Store)
	fullUser, err := a.Store().FindUserByEmail(context.Background(), "invite-team-limit-full@example.com")
	if err != nil {
		t.Fatalf("find full user: %v", err)
	}
	if err := st.CreateMember(context.Background(), &types.Member{
		ID:             "invite-team-limit-full-member",
		OrganizationID: org.ID,
		UserID:         fullUser.ID,
		Role:           "member",
		CreatedAt:      time.Now(),
	}); err != nil {
		t.Fatalf("create full member: %v", err)
	}
	if err := st.CreateTeamMember(context.Background(), &types.TeamMember{
		ID:        "invite-team-limit-full-team-member",
		TeamID:    team.ID,
		UserID:    fullUser.ID,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create full team member: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "invite-team-limit-rejected@example.com",
		"role":           "member",
		"teamId":         team.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("invite beyond team limit status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/accept-invitation", map[string]any{
		"invitationId": invitation.ID,
	}, pendingInviteeCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("accept beyond team limit status = %d body=%s", resp.StatusCode, data)
	}
	pendingInvitee, err := a.Store().FindUserByEmail(context.Background(), "invite-team-limit-pending@example.com")
	if err != nil {
		t.Fatalf("find pending invitee: %v", err)
	}
	if _, err := st.FindMemberByOrgAndUser(context.Background(), org.ID, pendingInvitee.ID); err == nil {
		t.Fatal("team-limited accept persisted organization member")
	}
	if _, err := st.FindTeamMember(context.Background(), team.ID, pendingInvitee.ID); err == nil {
		t.Fatal("team-limited accept persisted team member")
	}
	persistedInvitation, err := st.FindInvitationByID(context.Background(), invitation.ID)
	if err != nil {
		t.Fatalf("find pending invitation: %v", err)
	}
	if persistedInvitation.Status != constants.InvitationPending {
		t.Fatalf("invitation status = %q, want pending", persistedInvitation.Status)
	}
}

func TestOrganizationAcceptInvitationRespectsMembershipLimit(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			MembershipLimit: 1,
		})}
	})
	ownerCookies := signUp(t, a, "member-limit-owner@example.com")
	inviteeCookies := signUp(t, a, "member-limit-invitee@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Member Limit Org",
		"slug": "member-limit-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create limited organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode limited organization: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "member-limit-invitee@example.com",
		"role":           "member",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invite limited member status = %d body=%s", resp.StatusCode, data)
	}
	var invitation types.Invitation
	if err := json.Unmarshal(data, &invitation); err != nil {
		t.Fatalf("decode limited invitation: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/accept-invitation", map[string]any{
		"invitationId": invitation.ID,
	}, inviteeCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("limited accept invitation status = %d body=%s", resp.StatusCode, data)
	}

	st := a.Store().(*memory.Store)
	persistedInvitation, err := st.FindInvitationByID(context.Background(), invitation.ID)
	if err != nil {
		t.Fatalf("find limited invitation: %v", err)
	}
	if persistedInvitation.Status != constants.InvitationPending {
		t.Fatalf("limited invitation status = %q, want pending", persistedInvitation.Status)
	}
	invitee, err := a.Store().FindUserByEmail(context.Background(), "member-limit-invitee@example.com")
	if err != nil {
		t.Fatalf("find limited invitee: %v", err)
	}
	if _, err := st.FindMemberByOrgAndUser(context.Background(), org.ID, invitee.ID); err == nil {
		t.Fatalf("limited invitation accept persisted member")
	}
}

func TestOrganizationInvitationReadRejectCancelAndList(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{})}
	})
	ownerCookies := signUp(t, a, "invite-list-owner@example.com")
	recipientCookies := signUp(t, a, "invite-list-recipient@example.com")
	outsiderCookies := signUp(t, a, "invite-list-outsider@example.com")
	verifyUserEmail(t, a, "invite-list-recipient@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Invite List Org",
		"slug": "invite-list-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "invite-list-recipient@example.com",
		"role":           "member",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invite member status = %d body=%s", resp.StatusCode, data)
	}
	var invitation types.Invitation
	if err := json.Unmarshal(data, &invitation); err != nil {
		t.Fatalf("decode invitation: %v", err)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/get-invitation?id="+invitation.ID, nil, outsiderCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong recipient get invitation status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/get-invitation?id="+invitation.ID, nil, recipientCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get invitation status = %d body=%s", resp.StatusCode, data)
	}
	var inviteDetails struct {
		ID               string `json:"id"`
		OrganizationName string `json:"organizationName"`
		OrganizationSlug string `json:"organizationSlug"`
		InviterEmail     string `json:"inviterEmail"`
	}
	if err := json.Unmarshal(data, &inviteDetails); err != nil {
		t.Fatalf("decode invitation details: %v", err)
	}
	if inviteDetails.ID != invitation.ID || inviteDetails.OrganizationName != "Invite List Org" || inviteDetails.OrganizationSlug != "invite-list-org" || inviteDetails.InviterEmail != "invite-list-owner@example.com" {
		t.Fatalf("invitation details = %+v", inviteDetails)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/list-user-invitations", nil, recipientCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list user invitations status = %d body=%s", resp.StatusCode, data)
	}
	var userInvitations []types.Invitation
	if err := json.Unmarshal(data, &userInvitations); err != nil {
		t.Fatalf("decode user invitations: %v", err)
	}
	if len(userInvitations) != 1 || userInvitations[0].ID != invitation.ID {
		t.Fatalf("user invitations = %+v, want %s", userInvitations, invitation.ID)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/reject-invitation", map[string]any{
		"invitationId": invitation.ID,
	}, recipientCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reject invitation status = %d body=%s", resp.StatusCode, data)
	}
	var rejected struct {
		Invitation types.Invitation `json:"invitation"`
		Member     *types.Member    `json:"member"`
	}
	if err := json.Unmarshal(data, &rejected); err != nil {
		t.Fatalf("decode rejected invitation: %v", err)
	}
	if rejected.Invitation.Status != "rejected" || rejected.Member != nil {
		t.Fatalf("rejected response = %+v", rejected)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/list-user-invitations", nil, recipientCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list user invitations after reject status = %d body=%s", resp.StatusCode, data)
	}
	if err := json.Unmarshal(data, &userInvitations); err != nil {
		t.Fatalf("decode user invitations after reject: %v", err)
	}
	if len(userInvitations) != 0 {
		t.Fatalf("user invitations after reject = %+v, want none", userInvitations)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "invite-list-recipient@example.com",
		"role":           "member",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second invite member status = %d body=%s", resp.StatusCode, data)
	}
	var cancelInvitation types.Invitation
	if err := json.Unmarshal(data, &cancelInvitation); err != nil {
		t.Fatalf("decode cancel invitation: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/cancel-invitation", map[string]any{
		"invitationId": cancelInvitation.ID,
	}, outsiderCookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("outsider cancel invitation status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/cancel-invitation", map[string]any{
		"invitationId": cancelInvitation.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cancel invitation status = %d body=%s", resp.StatusCode, data)
	}
	var canceled types.Invitation
	if err := json.Unmarshal(data, &canceled); err != nil {
		t.Fatalf("decode canceled invitation: %v", err)
	}
	if canceled.Status != "canceled" {
		t.Fatalf("canceled invitation status = %q, want canceled", canceled.Status)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/list-invitations?organizationId="+org.ID, nil, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list org invitations status = %d body=%s", resp.StatusCode, data)
	}
	var orgInvitations []types.Invitation
	if err := json.Unmarshal(data, &orgInvitations); err != nil {
		t.Fatalf("decode org invitations: %v", err)
	}
	if len(orgInvitations) != 2 {
		t.Fatalf("org invitations = %+v, want two", orgInvitations)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/list-invitations?organizationId="+org.ID, nil, outsiderCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("outsider list org invitations status = %d body=%s", resp.StatusCode, data)
	}
}

func TestOrganizationHasPermissionUsesDefaultRoleMatrix(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{})}
	})
	ownerCookies := signUp(t, a, "permission-owner@example.com")
	adminCookies := signUp(t, a, "permission-admin@example.com")
	memberCookies := signUp(t, a, "permission-member@example.com")
	outsiderCookies := signUp(t, a, "permission-outsider@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Permission Org",
		"slug": "permission-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	st := a.Store().(*memory.Store)
	adminUser, err := a.Store().FindUserByEmail(context.Background(), "permission-admin@example.com")
	if err != nil {
		t.Fatalf("find admin: %v", err)
	}
	memberUser, err := a.Store().FindUserByEmail(context.Background(), "permission-member@example.com")
	if err != nil {
		t.Fatalf("find member: %v", err)
	}
	now := time.Now()
	if err := st.CreateMember(context.Background(), &types.Member{
		ID: "permission-admin-member", OrganizationID: org.ID, UserID: adminUser.ID,
		Role: "admin", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create admin member: %v", err)
	}
	if err := st.CreateMember(context.Background(), &types.Member{
		ID: "permission-regular-member", OrganizationID: org.ID, UserID: memberUser.ID,
		Role: "member", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create regular member: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/set-active", map[string]any{
		"organizationId": org.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set active organization status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/has-permission", map[string]any{
		"permissions": map[string][]string{"organization": []string{"delete"}},
	}, ownerCookies)
	assertPermissionResponse(t, resp, data, true)

	resp, data = doRequest(a, http.MethodPost, "/organization/has-permission", map[string]any{
		"organizationId": org.ID,
		"permissions":    map[string][]string{"organization": []string{"delete"}},
	}, adminCookies)
	assertPermissionResponse(t, resp, data, false)

	resp, data = doRequest(a, http.MethodPost, "/organization/has-permission", map[string]any{
		"organizationId": org.ID,
		"permissions":    map[string][]string{"organization": []string{"update"}, "team": []string{"create"}},
	}, adminCookies)
	assertPermissionResponse(t, resp, data, true)

	resp, data = doRequest(a, http.MethodPost, "/organization/has-permission", map[string]any{
		"organizationId": org.ID,
		"permission":     map[string][]string{"ac": []string{"read"}},
	}, memberCookies)
	assertPermissionResponse(t, resp, data, true)

	resp, data = doRequest(a, http.MethodPost, "/organization/has-permission", map[string]any{
		"organizationId": org.ID,
		"permissions":    map[string][]string{"team": []string{"create"}},
	}, memberCookies)
	assertPermissionResponse(t, resp, data, false)

	resp, data = doRequest(a, http.MethodPost, "/organization/has-permission", map[string]any{
		"organizationId": org.ID,
		"permissions":    map[string][]string{"team": []string{"create"}},
	}, outsiderCookies)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("outsider has-permission status = %d body=%s", resp.StatusCode, data)
	}
}

func TestOrganizationDynamicAccessControlRoleCRUDAndPermissions(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			DynamicAccessControl: &plugins.OrganizationDynamicAccessControlOptions{
				Enabled:                     true,
				MaximumRolesPerOrganization: 1,
			},
		})}
	})
	ownerCookies := signUp(t, a, "dynamic-owner@example.com")
	memberCookies := signUp(t, a, "dynamic-member@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Dynamic Org",
		"slug": "dynamic-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create-role", map[string]any{
		"organizationId": org.ID,
		"role":           "Reviewer",
		"permission": map[string][]string{
			"organization": []string{"update"},
			"ac":           []string{"read"},
		},
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create dynamic role status = %d body=%s", resp.StatusCode, data)
	}
	var createdRole struct {
		Success  bool                   `json:"success"`
		RoleData types.OrganizationRole `json:"roleData"`
	}
	if err := json.Unmarshal(data, &createdRole); err != nil {
		t.Fatalf("decode created role: %v", err)
	}
	if !createdRole.Success || createdRole.RoleData.Role != "reviewer" {
		t.Fatalf("created role = %+v", createdRole)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create-role", map[string]any{
		"organizationId": org.ID,
		"role":           "Publisher",
		"permission":     map[string][]string{"organization": []string{"update"}},
	}, ownerCookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("create role beyond limit status = %d body=%s", resp.StatusCode, data)
	}

	st := a.Store().(*memory.Store)
	memberUser, err := a.Store().FindUserByEmail(context.Background(), "dynamic-member@example.com")
	if err != nil {
		t.Fatalf("find member user: %v", err)
	}
	if err := st.CreateMember(context.Background(), &types.Member{
		ID:             "dynamic-reviewer-member",
		OrganizationID: org.ID,
		UserID:         memberUser.ID,
		Role:           "reviewer",
		CreatedAt:      time.Now(),
	}); err != nil {
		t.Fatalf("create reviewer member: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/has-permission", map[string]any{
		"organizationId": org.ID,
		"permissions":    map[string][]string{"organization": []string{"update"}},
	}, memberCookies)
	assertPermissionResponse(t, resp, data, true)

	resp, data = doRequest(a, http.MethodGet, "/organization/get-role?organizationId="+org.ID+"&roleName=reviewer", nil, memberCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get dynamic role status = %d body=%s", resp.StatusCode, data)
	}
	var gotRole types.OrganizationRole
	if err := json.Unmarshal(data, &gotRole); err != nil {
		t.Fatalf("decode got role: %v", err)
	}
	if gotRole.ID != createdRole.RoleData.ID {
		t.Fatalf("got role id = %q, want %q", gotRole.ID, createdRole.RoleData.ID)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/list-roles?organizationId="+org.ID, nil, memberCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list dynamic roles status = %d body=%s", resp.StatusCode, data)
	}
	var roles []types.OrganizationRole
	if err := json.Unmarshal(data, &roles); err != nil {
		t.Fatalf("decode roles: %v", err)
	}
	if len(roles) != 1 || roles[0].Role != "reviewer" {
		t.Fatalf("roles = %+v", roles)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/delete-role", map[string]any{
		"organizationId": org.ID,
		"roleName":       "reviewer",
	}, ownerCookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("delete assigned role status = %d body=%s", resp.StatusCode, data)
	}

	if _, err := st.UpdateMemberRole(context.Background(), "dynamic-reviewer-member", "member"); err != nil {
		t.Fatalf("reset reviewer member role: %v", err)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/update-role", map[string]any{
		"organizationId": org.ID,
		"roleId":         createdRole.RoleData.ID,
		"data": map[string]any{
			"roleName":   "Auditor",
			"permission": map[string][]string{"ac": []string{"read"}},
		},
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update dynamic role status = %d body=%s", resp.StatusCode, data)
	}
	var updatedRole struct {
		Success  bool                   `json:"success"`
		RoleData types.OrganizationRole `json:"roleData"`
	}
	if err := json.Unmarshal(data, &updatedRole); err != nil {
		t.Fatalf("decode updated role: %v", err)
	}
	if !updatedRole.Success || updatedRole.RoleData.Role != "auditor" {
		t.Fatalf("updated role = %+v", updatedRole)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/delete-role", map[string]any{
		"organizationId": org.ID,
		"roleId":         createdRole.RoleData.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete dynamic role status = %d body=%s", resp.StatusCode, data)
	}
}

func TestOrganizationCustomRolePermissionsApplyToRoutes(t *testing.T) {
	defaultTeamEnabled := false
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			DynamicAccessControl: &plugins.OrganizationDynamicAccessControlOptions{
				Enabled: true,
			},
			Teams: &plugins.OrganizationTeamsOptions{
				Enabled:               true,
				AllowRemovingAllTeams: true,
				DefaultTeam: &plugins.OrganizationDefaultTeamOptions{
					Enabled: &defaultTeamEnabled,
				},
			},
		})}
	})
	ownerCookies := signUp(t, a, "custom-route-owner@example.com")
	operatorCookies := signUp(t, a, "custom-route-operator@example.com")
	_ = signUp(t, a, "custom-route-target@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Custom Route Org",
		"slug": "custom-route-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create-role", map[string]any{
		"organizationId": org.ID,
		"role":           "Operator",
		"permission": map[string][]string{
			"invitation": []string{"create"},
			"team":       []string{"create", "update", "delete"},
			"member":     []string{"update", "delete"},
		},
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create custom route role status = %d body=%s", resp.StatusCode, data)
	}

	operator, err := a.Store().FindUserByEmail(context.Background(), "custom-route-operator@example.com")
	if err != nil {
		t.Fatalf("find operator: %v", err)
	}
	target, err := a.Store().FindUserByEmail(context.Background(), "custom-route-target@example.com")
	if err != nil {
		t.Fatalf("find target: %v", err)
	}
	for _, member := range []struct {
		userID string
		role   string
	}{
		{operator.ID, "operator"},
		{target.ID, "member"},
	} {
		resp, data = doRequest(a, http.MethodPost, "/organization/add-member", map[string]any{
			"organizationId": org.ID,
			"userId":         member.userID,
			"role":           member.role,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("add %s member status = %d body=%s", member.role, resp.StatusCode, data)
		}
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "custom-route-invite@example.com",
		"role":           "member",
	}, operatorCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("custom role invite status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create-team", map[string]any{
		"organizationId": org.ID,
		"name":           "Operator Team",
	}, operatorCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("custom role create team status = %d body=%s", resp.StatusCode, data)
	}
	var team types.Team
	if err := json.Unmarshal(data, &team); err != nil {
		t.Fatalf("decode operator team: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/update-team", map[string]any{
		"teamId":         team.ID,
		"organizationId": org.ID,
		"name":           "Updated Operator Team",
	}, operatorCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("custom role update team status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/add-team-member", map[string]any{
		"organizationId": org.ID,
		"teamId":         team.ID,
		"userId":         target.ID,
	}, operatorCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("custom role add team member status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/remove-team-member", map[string]any{
		"organizationId": org.ID,
		"teamId":         team.ID,
		"userId":         target.ID,
	}, operatorCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("custom role remove team member status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/remove-team", map[string]any{
		"organizationId": org.ID,
		"teamId":         team.ID,
	}, operatorCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("custom role remove team status = %d body=%s", resp.StatusCode, data)
	}
}

func TestOrganizationValidatesInviteAndUpdateRoles(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{
			Roles: map[string]map[string][]string{
				"inviter": {
					"invitation": []string{"create"},
				},
			},
			DynamicAccessControl: &plugins.OrganizationDynamicAccessControlOptions{
				Enabled: true,
			},
		})}
	})
	ownerCookies := signUp(t, a, "role-validation-owner@example.com")
	inviterCookies := signUp(t, a, "role-validation-inviter@example.com")
	_ = signUp(t, a, "role-validation-target@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name": "Role Validation Org",
		"slug": "role-validation-org",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var org types.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}
	inviter, err := a.Store().FindUserByEmail(context.Background(), "role-validation-inviter@example.com")
	if err != nil {
		t.Fatalf("find inviter: %v", err)
	}
	target, err := a.Store().FindUserByEmail(context.Background(), "role-validation-target@example.com")
	if err != nil {
		t.Fatalf("find target: %v", err)
	}
	for _, member := range []struct {
		userID string
		role   string
	}{
		{inviter.ID, "inviter"},
		{target.ID, "member"},
	} {
		resp, data = doRequest(a, http.MethodPost, "/organization/add-member", map[string]any{
			"organizationId": org.ID,
			"userId":         member.userID,
			"role":           member.role,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("add %s member status = %d body=%s", member.role, resp.StatusCode, data)
		}
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "role-validation-static@example.com",
		"role":           "member",
	}, inviterCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("static role invite permission status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "role-validation-unknown@example.com",
		"role":           "ghost",
	}, ownerCookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown invite role status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/create-role", map[string]any{
		"organizationId": org.ID,
		"role":           "Reviewer",
		"permission":     map[string][]string{"ac": []string{"read"}},
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create dynamic validation role status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": org.ID,
		"email":          "role-validation-dynamic@example.com",
		"role":           "reviewer",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dynamic invite role status = %d body=%s", resp.StatusCode, data)
	}

	member, err := a.Store().(*memory.Store).FindMemberByOrgAndUser(context.Background(), org.ID, target.ID)
	if err != nil {
		t.Fatalf("find target member: %v", err)
	}
	resp, data = doRequest(a, http.MethodPost, "/organization/update-member-role", map[string]any{
		"organizationId": org.ID,
		"memberId":       member.ID,
		"role":           "ghost",
	}, ownerCookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown update role status = %d body=%s", resp.StatusCode, data)
	}
}

func TestOrganizationCoreRoutesFollowMembershipPermissions(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{})}
	})
	ownerCookies := signUp(t, a, "core-owner@example.com")
	adminCookies := signUp(t, a, "core-admin@example.com")
	memberCookies := signUp(t, a, "core-member@example.com")
	outsiderCookies := signUp(t, a, "core-outsider@example.com")

	resp, data := doRequest(a, http.MethodPost, "/organization/create", map[string]any{
		"name":     "Core Org",
		"slug":     "core-org",
		"metadata": map[string]any{"tier": "free"},
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create organization status = %d body=%s", resp.StatusCode, data)
	}
	var created struct {
		ID       string         `json:"id"`
		Name     string         `json:"name"`
		Slug     string         `json:"slug"`
		Metadata map[string]any `json:"metadata"`
		Members  []types.Member `json:"members"`
	}
	if err := json.Unmarshal(data, &created); err != nil {
		t.Fatalf("decode created organization: %v", err)
	}
	if created.Name != "Core Org" || created.Slug != "core-org" || len(created.Members) != 1 || created.Members[0].Role != "owner" {
		t.Fatalf("created organization = %+v", created)
	}
	if created.Metadata["tier"] != "free" {
		t.Fatalf("created metadata = %+v, want tier=free", created.Metadata)
	}

	st := a.Store().(*memory.Store)
	adminUser, err := a.Store().FindUserByEmail(context.Background(), "core-admin@example.com")
	if err != nil {
		t.Fatalf("find admin: %v", err)
	}
	memberUser, err := a.Store().FindUserByEmail(context.Background(), "core-member@example.com")
	if err != nil {
		t.Fatalf("find member: %v", err)
	}
	now := time.Now()
	if err := st.CreateMember(context.Background(), &types.Member{
		ID: "core-admin-member", OrganizationID: created.ID, UserID: adminUser.ID, Role: "admin", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create admin member: %v", err)
	}
	if err := st.CreateMember(context.Background(), &types.Member{
		ID: "core-regular-member", OrganizationID: created.ID, UserID: memberUser.ID, Role: "member", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create regular member: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/update", map[string]any{
		"organizationId": created.ID,
		"data": map[string]any{
			"name":     "Core Org Updated",
			"slug":     "core-org-updated",
			"metadata": map[string]any{"tier": "pro", "seats": float64(10)},
		},
	}, adminCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin update organization status = %d body=%s", resp.StatusCode, data)
	}
	var updated struct {
		ID       string         `json:"id"`
		Name     string         `json:"name"`
		Slug     string         `json:"slug"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := json.Unmarshal(data, &updated); err != nil {
		t.Fatalf("decode updated organization: %v", err)
	}
	if updated.Name != "Core Org Updated" || updated.Slug != "core-org-updated" {
		t.Fatalf("updated organization = %+v", updated)
	}
	if updated.Metadata["tier"] != "pro" || updated.Metadata["seats"] != float64(10) {
		t.Fatalf("updated metadata = %+v", updated.Metadata)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/update", map[string]any{
		"organizationId": created.ID,
		"data":           map[string]any{"name": "Denied"},
	}, memberCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member update organization status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/set-active", map[string]any{
		"organizationSlug": "core-org-updated",
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set active by slug status = %d body=%s", resp.StatusCode, data)
	}
	var active struct {
		ID       string         `json:"id"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := json.Unmarshal(data, &active); err != nil {
		t.Fatalf("decode active organization: %v", err)
	}
	if active.ID != created.ID {
		t.Fatalf("active organization id = %q, want %q", active.ID, created.ID)
	}
	if active.Metadata["tier"] != "pro" {
		t.Fatalf("active organization metadata = %+v", active.Metadata)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/set-active", map[string]any{
		"organizationId": created.ID,
	}, outsiderCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("outsider set active status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodGet, "/organization/get-full-organization?organizationSlug=core-org-updated", nil, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get full organization status = %d body=%s", resp.StatusCode, data)
	}
	var full struct {
		ID      string         `json:"id"`
		Members []types.Member `json:"members"`
	}
	if err := json.Unmarshal(data, &full); err != nil {
		t.Fatalf("decode full organization: %v", err)
	}
	if full.ID != created.ID || len(full.Members) != 3 {
		t.Fatalf("full organization = %+v", full)
	}
	resp, data = doRequest(a, http.MethodGet, "/organization/get-full-organization?organizationId="+created.ID, nil, outsiderCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("outsider get full organization status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/delete", map[string]any{
		"organizationId": created.ID,
	}, adminCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin delete organization status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/set-active", map[string]any{
		"organizationId": nil,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK || string(data) != "null" {
		t.Fatalf("clear active organization status = %d body=%s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/organization/delete", map[string]any{
		"organizationId": created.ID,
	}, ownerCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner delete organization status = %d body=%s", resp.StatusCode, data)
	}
	var deleted struct {
		ID       string         `json:"id"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := json.Unmarshal(data, &deleted); err != nil {
		t.Fatalf("decode deleted organization: %v", err)
	}
	if deleted.ID != created.ID {
		t.Fatalf("deleted organization id = %q, want %q", deleted.ID, created.ID)
	}
	if _, err := st.FindOrganizationByID(context.Background(), created.ID); err == nil {
		t.Fatal("expected organization to be deleted")
	}
}

func assertPermissionResponse(t *testing.T, resp *http.Response, data []byte, want bool) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("has-permission status = %d body=%s", resp.StatusCode, data)
	}
	var out struct {
		Error   any  `json:"error"`
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode has-permission response: %v", err)
	}
	if out.Error != nil || out.Success != want {
		t.Fatalf("has-permission response = %+v, want success=%v", out, want)
	}
}
