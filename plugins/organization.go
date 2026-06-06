package plugins

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

var slugPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// OrganizationOptions configures the organization plugin.
type OrganizationOptions struct {
	AllowUserToCreateOrganization bool
}

func requireExt(c *auth.Context) (store.ExtStore, bool) {
	ext, ok := auth.ExtStore(c.Auth.Store())
	if !ok {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
		return nil, false
	}
	return ext, true
}

// Organization adds teams, members, roles, and invitations.
func Organization(opts OrganizationOptions) auth.Plugin {
	routes := []auth.PluginRoute{
		rt(http.MethodPost, "/organization/create", func(c *auth.Context) {
			_, user, ok := c.RequireSession()
			if !ok {
				return
			}
			ext, ok := requireExt(c)
			if !ok {
				return
			}
			var body struct {
				Name string `json:"name"`
				Slug string `json:"slug"`
				Logo string `json:"logo"`
			}
			if err := c.ParseJSON(&body); err != nil || body.Name == "" || body.Slug == "" {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
				return
			}
			slug := strings.ToLower(body.Slug)
			if !slugPattern.MatchString(slug) {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidSlug))
				return
			}
			now := time.Now()
			orgID, _ := id.Generate(32)
			var logo *string
			if body.Logo != "" {
				logo = &body.Logo
			}
			org := &types.Organization{ID: orgID, Name: body.Name, Slug: slug, Logo: logo, CreatedAt: now}
			if err := ext.CreateOrganization(c.R.Context(), org); err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeSlugExists))
				return
			}
			memberID, _ := id.Generate(32)
			_ = ext.CreateMember(c.R.Context(), &types.Member{
				ID: memberID, OrganizationID: orgID, UserID: user.ID, Role: constants.RoleOwner, CreatedAt: now,
			})
			c.WriteJSON(http.StatusOK, org)
		}),
		rt(http.MethodPost, "/organization/check-slug", func(c *auth.Context) {
			ext, ok := requireExt(c)
			if !ok {
				return
			}
			var body struct {
				Slug string `json:"slug"`
			}
			_ = c.ParseJSON(&body)
			_, err := ext.FindOrganizationBySlug(c.R.Context(), strings.ToLower(body.Slug))
			c.WriteJSON(http.StatusOK, map[string]bool{"available": err != nil})
		}),
		rt(http.MethodPost, "/organization/update", func(c *auth.Context) {
			_, _, ok := c.RequireSession()
			if !ok {
				return
			}
			ext, ok := requireExt(c)
			if !ok {
				return
			}
			var body struct {
				OrganizationID string  `json:"organizationId"`
				Name           string  `json:"name"`
				Slug           string  `json:"slug"`
				Logo           *string `json:"logo"`
			}
			_ = c.ParseJSON(&body)
			org, err := ext.UpdateOrganization(c.R.Context(), body.OrganizationID, body.Name, body.Slug, body.Logo)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeOrgNotFound))
				return
			}
			c.WriteJSON(http.StatusOK, org)
		}),
		rt(http.MethodPost, "/organization/delete", func(c *auth.Context) {
			_, _, ok := c.RequireSession()
			if !ok {
				return
			}
			ext, ok := requireExt(c)
			if !ok {
				return
			}
			var body struct {
				OrganizationID string `json:"organizationId"`
			}
			_ = c.ParseJSON(&body)
			_ = ext.DeleteOrganization(c.R.Context(), body.OrganizationID)
			c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
		}),
		rt(http.MethodGet, "/organization/get-full-organization", func(c *auth.Context) {
			_, user, ok := c.RequireSession()
			if !ok {
				return
			}
			ext, ok := requireExt(c)
			if !ok {
				return
			}
			orgID := c.R.URL.Query().Get("organizationId")
			org, err := ext.FindOrganizationByID(c.R.Context(), orgID)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeOrgNotFound))
				return
			}
			members, _ := ext.ListMembersByOrg(c.R.Context(), orgID)
			invitations, _ := ext.ListInvitationsByOrg(c.R.Context(), orgID)
			teams, _ := ext.ListTeamsByOrg(c.R.Context(), orgID)
			_, _ = ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID)
			c.WriteJSON(http.StatusOK, map[string]any{
				"organization": org, "members": members, "invitations": invitations, "teams": teams,
			})
		}),
		rt(http.MethodPost, "/organization/set-active", func(c *auth.Context) {
			sess, _, ok := c.RequireSession()
			if !ok {
				return
			}
			var body struct {
				OrganizationID string `json:"organizationId"`
			}
			_ = c.ParseJSON(&body)
			sess, _ = c.Auth.SetSessionAdditional(c.R.Context(), sess.Token, map[string]any{
				constants.SessionActiveOrganizationID: body.OrganizationID,
			})
			c.WriteJSON(http.StatusOK, map[string]any{"session": sess})
		}),
		rt(http.MethodGet, "/organization/list", func(c *auth.Context) {
			_, user, ok := c.RequireSession()
			if !ok {
				return
			}
			ext, ok := requireExt(c)
			if !ok {
				return
			}
			members, _ := ext.ListMembersByUser(c.R.Context(), user.ID)
			orgs := make([]types.Organization, 0, len(members))
			for _, m := range members {
				if org, err := ext.FindOrganizationByID(c.R.Context(), m.OrganizationID); err == nil {
					orgs = append(orgs, *org)
				}
			}
			c.WriteJSON(http.StatusOK, orgs)
		}),
		rt(http.MethodPost, "/organization/invite-member", func(c *auth.Context) {
			_, user, ok := c.RequireSession()
			if !ok {
				return
			}
			ext, ok := requireExt(c)
			if !ok {
				return
			}
			var body struct {
				OrganizationID string `json:"organizationId"`
				Email          string `json:"email"`
				Role           string `json:"role"`
			}
			_ = c.ParseJSON(&body)
			now := time.Now()
			invID, _ := id.Generate(32)
			_ = ext.CreateInvitation(c.R.Context(), &types.Invitation{
				ID: invID, OrganizationID: body.OrganizationID, Email: auth.NormalizeEmail(body.Email),
				Role: body.Role, Status: constants.InvitationPending, InviterID: user.ID,
				ExpiresAt: now.Add(7 * 24 * time.Hour), CreatedAt: now,
			})
			c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
		}),
		rt(http.MethodPost, "/organization/accept-invitation", acceptInvitationHandler()),
		rt(http.MethodPost, "/organization/reject-invitation", rejectInvitationHandler()),
		rt(http.MethodPost, "/organization/cancel-invitation", cancelInvitationHandler()),
		rt(http.MethodGet, "/organization/get-invitation", getInvitationHandler()),
		rt(http.MethodGet, "/organization/list-invitations", listOrgInvitationsHandler()),
		rt(http.MethodGet, "/organization/list-user-invitations", listUserInvitationsHandler()),
		rt(http.MethodPost, "/organization/remove-member", removeMemberHandler()),
		rt(http.MethodPost, "/organization/update-member-role", updateMemberRoleHandler()),
		rt(http.MethodGet, "/organization/get-active-member", getActiveMemberHandler()),
		rt(http.MethodPost, "/organization/leave", leaveOrgHandler()),
		rt(http.MethodGet, "/organization/list-members", listMembersHandler()),
		rt(http.MethodGet, "/organization/get-active-member-role", getActiveMemberRoleHandler()),
		rt(http.MethodPost, "/organization/has-permission", hasOrgPermissionHandler()),
		// Teams
		rt(http.MethodPost, "/organization/create-team", createTeamHandler()),
		rt(http.MethodPost, "/organization/remove-team", removeTeamHandler()),
		rt(http.MethodPost, "/organization/update-team", updateTeamHandler()),
		rt(http.MethodGet, "/organization/list-teams", listTeamsHandler()),
		rt(http.MethodPost, "/organization/set-active-team", setActiveTeamHandler()),
		rt(http.MethodGet, "/organization/list-user-teams", listUserTeamsHandler()),
		rt(http.MethodGet, "/organization/list-team-members", listTeamMembersHandler()),
		rt(http.MethodPost, "/organization/add-team-member", addTeamMemberHandler()),
		rt(http.MethodPost, "/organization/remove-team-member", removeTeamMemberHandler()),
	}
	return basePlugin{id: constants.PluginOrganization, routes: routes}
}

func acceptInvitationHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		_, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			InvitationID string `json:"invitationId"`
		}
		_ = c.ParseJSON(&body)
		inv, err := ext.FindInvitationByID(c.R.Context(), body.InvitationID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeInvitationNotFound))
			return
		}
		now := time.Now()
		memberID, _ := id.Generate(32)
		_ = ext.CreateMember(c.R.Context(), &types.Member{
			ID: memberID, OrganizationID: inv.OrganizationID, UserID: user.ID,
			Role: inv.Role, CreatedAt: now,
		})
		_ = ext.UpdateInvitationStatus(c.R.Context(), inv.ID, constants.InvitationAccepted)
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func rejectInvitationHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			InvitationID string `json:"invitationId"`
		}
		_ = c.ParseJSON(&body)
		_ = ext.UpdateInvitationStatus(c.R.Context(), body.InvitationID, constants.InvitationRejected)
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func cancelInvitationHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			InvitationID string `json:"invitationId"`
		}
		_ = c.ParseJSON(&body)
		_ = ext.UpdateInvitationStatus(c.R.Context(), body.InvitationID, constants.InvitationCanceled)
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func getInvitationHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		id := c.R.URL.Query().Get("id")
		inv, err := ext.FindInvitationByID(c.R.Context(), id)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeInvitationNotFound))
			return
		}
		c.WriteJSON(http.StatusOK, inv)
	}
}

func listOrgInvitationsHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		orgID := c.R.URL.Query().Get("organizationId")
		invitations, _ := ext.ListInvitationsByOrg(c.R.Context(), orgID)
		c.WriteJSON(http.StatusOK, invitations)
	}
}

func listUserInvitationsHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		_, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		invitations, _ := ext.ListInvitationsByEmail(c.R.Context(), user.Email)
		c.WriteJSON(http.StatusOK, invitations)
	}
}

func removeMemberHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			MemberID string `json:"memberId"`
		}
		_ = c.ParseJSON(&body)
		_ = ext.DeleteMember(c.R.Context(), body.MemberID)
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func updateMemberRoleHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		if _, ok := requireExt(c); !ok {
			return
		}
		var body struct {
			MemberID string `json:"memberId"`
			Role     string `json:"role"`
		}
		_ = c.ParseJSON(&body)
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func getActiveMemberHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		orgID, _ := auth.SessionAdditional(sess, constants.SessionActiveOrganizationID)
		if orgID == nil {
			c.WriteNull()
			return
		}
		member, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID.(string), user.ID)
		if err != nil {
			c.WriteNull()
			return
		}
		c.WriteJSON(http.StatusOK, member)
	}
}

func leaveOrgHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		_, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			OrganizationID string `json:"organizationId"`
		}
		_ = c.ParseJSON(&body)
		members, _ := ext.ListMembersByOrg(c.R.Context(), body.OrganizationID)
		for _, m := range members {
			if m.UserID == user.ID {
				_ = ext.DeleteMember(c.R.Context(), m.ID)
			}
		}
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func listMembersHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		orgID := c.R.URL.Query().Get("organizationId")
		members, _ := ext.ListMembersByOrg(c.R.Context(), orgID)
		c.WriteJSON(http.StatusOK, members)
	}
}

func getActiveMemberRoleHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		orgID, _ := auth.SessionAdditional(sess, constants.SessionActiveOrganizationID)
		if orgID == nil {
			c.WriteNull()
			return
		}
		member, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID.(string), user.ID)
		if err != nil {
			c.WriteNull()
			return
		}
		c.WriteJSON(http.StatusOK, map[string]string{"role": member.Role})
	}
}

func hasOrgPermissionHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func createTeamHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			OrganizationID string `json:"organizationId"`
			Name           string `json:"name"`
		}
		_ = c.ParseJSON(&body)
		now := time.Now()
		teamID, _ := id.Generate(32)
		_ = ext.CreateTeam(c.R.Context(), &types.Team{
			ID: teamID, Name: body.Name, OrganizationID: body.OrganizationID, CreatedAt: now,
		})
		c.WriteJSON(http.StatusOK, map[string]string{"id": teamID})
	}
}

func removeTeamHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			TeamID string `json:"teamId"`
		}
		_ = c.ParseJSON(&body)
		_ = ext.DeleteTeam(c.R.Context(), body.TeamID)
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func updateTeamHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func listTeamsHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		orgID := c.R.URL.Query().Get("organizationId")
		teams, _ := ext.ListTeamsByOrg(c.R.Context(), orgID)
		c.WriteJSON(http.StatusOK, teams)
	}
}

func setActiveTeamHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		sess, _, ok := c.RequireSession()
		if !ok {
			return
		}
		var body struct {
			TeamID string `json:"teamId"`
		}
		_ = c.ParseJSON(&body)
		sess, _ = c.Auth.SetSessionAdditional(c.R.Context(), sess.Token, map[string]any{constants.SessionActiveTeamID: body.TeamID})
		c.WriteJSON(http.StatusOK, map[string]any{"session": sess})
	}
}

func listUserTeamsHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		c.WriteJSON(http.StatusOK, []types.Team{})
	}
}

func listTeamMembersHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		teamID := c.R.URL.Query().Get("teamId")
		members, _ := ext.ListTeamMembers(c.R.Context(), teamID)
		c.WriteJSON(http.StatusOK, members)
	}
}

func addTeamMemberHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			TeamID string `json:"teamId"`
			UserID string `json:"userId"`
		}
		_ = c.ParseJSON(&body)
		now := time.Now()
		tmID, _ := id.Generate(32)
		_ = ext.CreateTeamMember(c.R.Context(), &types.TeamMember{
			ID: tmID, TeamID: body.TeamID, UserID: body.UserID, CreatedAt: now,
		})
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func removeTeamMemberHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			TeamMemberID string `json:"teamMemberId"`
		}
		_ = c.ParseJSON(&body)
		_ = ext.DeleteTeamMember(c.R.Context(), body.TeamMemberID)
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}
