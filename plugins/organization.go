package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	internalcrypto "github.com/patrickkabwe/betterauth-go/internal/crypto"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

var slugPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// OrganizationOptions configures the organization plugin.
type OrganizationOptions struct {
	AllowUserToCreateOrganization        *bool
	AllowUserToCreateOrganizationFunc    func(context.Context, types.User) (bool, error)
	CreatorRole                          string
	OrganizationLimit                    int
	OrganizationLimitReached             func(context.Context, types.User) (bool, error)
	MembershipLimit                      int
	MembershipLimitFunc                  func(context.Context, types.User, types.Organization) (int, error)
	InvitationExpiresIn                  time.Duration
	InvitationLimit                      int
	InvitationLimitFunc                  func(context.Context, OrganizationInvitationLimitData) (int, error)
	CancelPendingInvitationsOnReInvite   bool
	RequireEmailVerificationOnInvitation *bool
	SendInvitationEmail                  func(context.Context, OrganizationInvitationEmailData) error
	DisableOrganizationDeletion          bool
	OrganizationHooks                    *OrganizationHooks
	Roles                                map[string]map[string][]string
	DynamicAccessControl                 *OrganizationDynamicAccessControlOptions
	Teams                                *OrganizationTeamsOptions
}

// OrganizationHooks configures organization lifecycle callbacks.
type OrganizationHooks struct {
	BeforeCreateOrganization func(context.Context, OrganizationCreateHookData) (*OrganizationCreateData, error)
	AfterCreateOrganization  func(context.Context, OrganizationCreatedHookData) error
	BeforeUpdateOrganization func(context.Context, OrganizationUpdateHookData) (*OrganizationUpdateData, error)
	AfterUpdateOrganization  func(context.Context, OrganizationUpdatedHookData) error
	BeforeDeleteOrganization func(context.Context, OrganizationDeleteHookData) error
	AfterDeleteOrganization  func(context.Context, OrganizationDeleteHookData) error
	BeforeAddMember          func(context.Context, OrganizationMemberAddHookData) (*OrganizationMemberCreateData, error)
	AfterAddMember           func(context.Context, OrganizationMemberHookData) error
	BeforeRemoveMember       func(context.Context, OrganizationMemberHookData) error
	AfterRemoveMember        func(context.Context, OrganizationMemberHookData) error
	BeforeUpdateMemberRole   func(context.Context, OrganizationMemberRoleUpdateHookData) (*OrganizationMemberRoleUpdateData, error)
	AfterUpdateMemberRole    func(context.Context, OrganizationMemberRoleUpdatedHookData) error
	BeforeCreateInvitation   func(context.Context, OrganizationInvitationCreateHookData) (*OrganizationInvitationCreateData, error)
	AfterCreateInvitation    func(context.Context, OrganizationInvitationHookData) error
	BeforeAcceptInvitation   func(context.Context, OrganizationInvitationUserHookData) error
	AfterAcceptInvitation    func(context.Context, OrganizationInvitationAcceptHookData) error
	BeforeRejectInvitation   func(context.Context, OrganizationInvitationUserHookData) error
	AfterRejectInvitation    func(context.Context, OrganizationInvitationUserHookData) error
	BeforeCancelInvitation   func(context.Context, OrganizationInvitationCancelHookData) error
	AfterCancelInvitation    func(context.Context, OrganizationInvitationCancelHookData) error
	BeforeCreateTeam         func(context.Context, OrganizationTeamCreateHookData) (*OrganizationTeamCreateData, error)
	AfterCreateTeam          func(context.Context, OrganizationTeamHookData) error
	BeforeUpdateTeam         func(context.Context, OrganizationTeamUpdateHookData) (*OrganizationTeamUpdateData, error)
	AfterUpdateTeam          func(context.Context, OrganizationTeamHookData) error
	BeforeDeleteTeam         func(context.Context, OrganizationTeamHookData) error
	AfterDeleteTeam          func(context.Context, OrganizationTeamHookData) error
	BeforeAddTeamMember      func(context.Context, OrganizationTeamMemberHookData) error
	AfterAddTeamMember       func(context.Context, OrganizationTeamMemberHookData) error
	BeforeRemoveTeamMember   func(context.Context, OrganizationTeamMemberHookData) error
	AfterRemoveTeamMember    func(context.Context, OrganizationTeamMemberHookData) error
}

// OrganizationCreateData is mutable data used before organization creation.
type OrganizationCreateData struct {
	Name     string
	Slug     string
	Logo     *string
	Metadata string
}

// OrganizationUpdateData is mutable data used before organization updates.
type OrganizationUpdateData struct {
	Name     string
	Slug     string
	Logo     *string
	Metadata *string
}

// OrganizationCreateHookData is passed to BeforeCreateOrganization.
type OrganizationCreateHookData struct {
	Organization OrganizationCreateData
	User         types.User
}

// OrganizationCreatedHookData is passed to AfterCreateOrganization.
type OrganizationCreatedHookData struct {
	Organization types.Organization
	Member       types.Member
	User         types.User
}

// OrganizationUpdateHookData is passed to BeforeUpdateOrganization.
type OrganizationUpdateHookData struct {
	Organization OrganizationUpdateData
	User         types.User
	Member       types.Member
}

// OrganizationUpdatedHookData is passed to AfterUpdateOrganization.
type OrganizationUpdatedHookData struct {
	Organization types.Organization
	User         types.User
	Member       types.Member
}

// OrganizationDeleteHookData is passed to delete organization hooks.
type OrganizationDeleteHookData struct {
	Organization types.Organization
	User         types.User
}

// OrganizationMemberCreateData is mutable data used before member creation.
type OrganizationMemberCreateData struct {
	UserID         string
	OrganizationID string
	Role           string
}

// OrganizationMemberAddHookData is passed to BeforeAddMember.
type OrganizationMemberAddHookData struct {
	Member       OrganizationMemberCreateData
	User         types.User
	Organization types.Organization
}

// OrganizationMemberHookData is passed to member create/remove hooks.
type OrganizationMemberHookData struct {
	Member       types.Member
	User         types.User
	Organization types.Organization
}

// OrganizationMemberRoleUpdateData is mutable data used before role updates.
type OrganizationMemberRoleUpdateData struct {
	Role string
}

// OrganizationMemberRoleUpdateHookData is passed to BeforeUpdateMemberRole.
type OrganizationMemberRoleUpdateHookData struct {
	Member       types.Member
	NewRole      string
	User         types.User
	Organization types.Organization
}

// OrganizationMemberRoleUpdatedHookData is passed to AfterUpdateMemberRole.
type OrganizationMemberRoleUpdatedHookData struct {
	Member       types.Member
	PreviousRole string
	User         types.User
	Organization types.Organization
}

// OrganizationInvitationCreateData is mutable data used before invitation creation.
type OrganizationInvitationCreateData struct {
	Email          string
	Role           string
	OrganizationID string
	InviterID      string
	TeamID         string
	ExpiresAt      time.Time
}

// OrganizationInvitationCreateHookData is passed to BeforeCreateInvitation.
type OrganizationInvitationCreateHookData struct {
	Invitation   OrganizationInvitationCreateData
	Inviter      types.User
	Organization types.Organization
}

// OrganizationInvitationHookData is passed to invitation create hooks.
type OrganizationInvitationHookData struct {
	Invitation   types.Invitation
	Inviter      types.User
	Organization types.Organization
}

// OrganizationInvitationUserHookData is passed to invitation recipient hooks.
type OrganizationInvitationUserHookData struct {
	Invitation   types.Invitation
	User         types.User
	Organization types.Organization
}

// OrganizationInvitationAcceptHookData is passed to AfterAcceptInvitation.
type OrganizationInvitationAcceptHookData struct {
	Invitation   types.Invitation
	Member       types.Member
	User         types.User
	Organization types.Organization
}

// OrganizationInvitationCancelHookData is passed to invitation cancel hooks.
type OrganizationInvitationCancelHookData struct {
	Invitation   types.Invitation
	CancelledBy  types.User
	Organization types.Organization
}

// OrganizationTeamCreateData is mutable data used before team creation.
type OrganizationTeamCreateData struct {
	Name           string
	OrganizationID string
}

// OrganizationTeamUpdateData is mutable data used before team updates.
type OrganizationTeamUpdateData struct {
	Name string
}

// OrganizationTeamCreateHookData is passed to BeforeCreateTeam.
type OrganizationTeamCreateHookData struct {
	Team         OrganizationTeamCreateData
	User         *types.User
	Organization types.Organization
}

// OrganizationTeamUpdateHookData is passed to BeforeUpdateTeam.
type OrganizationTeamUpdateHookData struct {
	Team         types.Team
	Updates      OrganizationTeamUpdateData
	User         types.User
	Organization types.Organization
}

// OrganizationTeamHookData is passed to team lifecycle hooks.
type OrganizationTeamHookData struct {
	Team         types.Team
	User         *types.User
	Organization types.Organization
}

// OrganizationTeamMemberHookData is passed to team member hooks.
type OrganizationTeamMemberHookData struct {
	TeamMember   types.TeamMember
	Team         types.Team
	User         types.User
	Organization types.Organization
}

// OrganizationInvitationEmailData is passed to SendInvitationEmail.
type OrganizationInvitationEmailData struct {
	ID           string
	Role         string
	Email        string
	Organization types.Organization
	Invitation   types.Invitation
	Inviter      types.Member
	InviterUser  types.User
	Request      *http.Request
}

// OrganizationInvitationLimitData is passed to dynamic invitation limits.
type OrganizationInvitationLimitData struct {
	User         types.User
	Organization types.Organization
	Member       types.Member
}

// OrganizationDynamicAccessControlOptions configures custom organization roles.
type OrganizationDynamicAccessControlOptions struct {
	Enabled                         bool
	MaximumRolesPerOrganization     int
	MaximumRolesPerOrganizationFunc func(context.Context, string) (int, error)
}

// OrganizationTeamsOptions configures organization team support.
type OrganizationTeamsOptions struct {
	Enabled                   bool
	DefaultTeam               *OrganizationDefaultTeamOptions
	MaximumTeams              int
	MaximumTeamsFunc          func(context.Context, OrganizationMaximumTeamsData) (int, error)
	MaximumMembersPerTeam     int
	MaximumMembersPerTeamFunc func(context.Context, OrganizationMaximumMembersPerTeamData) (int, error)
	AllowRemovingAllTeams     bool
}

// OrganizationDefaultTeamOptions configures default team creation.
type OrganizationDefaultTeamOptions struct {
	Enabled                 *bool
	CustomCreateDefaultTeam func(context.Context, types.Organization, types.User) (*types.Team, error)
}

// OrganizationMaximumTeamsData is passed to dynamic team limits.
type OrganizationMaximumTeamsData struct {
	OrganizationID string
	Session        *types.Session
	User           *types.User
}

// OrganizationMaximumMembersPerTeamData is passed to dynamic team member limits.
type OrganizationMaximumMembersPerTeamData struct {
	TeamID         string
	OrganizationID string
	Session        *types.Session
	User           *types.User
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
			sess, user, ok := c.RequireSession()
			if !ok {
				return
			}
			ext, ok := requireExt(c)
			if !ok {
				return
			}
			var body struct {
				Name                          string `json:"name"`
				Slug                          string `json:"slug"`
				Logo                          string `json:"logo"`
				Metadata                      string `json:"-"`
				KeepCurrentActiveOrganization bool   `json:"keepCurrentActiveOrganization"`
			}
			var raw map[string]json.RawMessage
			if err := c.ParseJSON(&raw); err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
				return
			}
			if err := decodeOrganizationCreateBody(raw, &body); err != nil || body.Name == "" || body.Slug == "" {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
				return
			}
			allowed, err := organizationCreationAllowed(c.R.Context(), opts, user)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
			if !allowed {
				c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
				return
			}
			limitReached, err := organizationLimitReached(c.R.Context(), ext, opts, user)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
			if limitReached {
				c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
				return
			}
			var logo *string
			if body.Logo != "" {
				logo = &body.Logo
			}
			createData := OrganizationCreateData{
				Name:     body.Name,
				Slug:     body.Slug,
				Logo:     logo,
				Metadata: body.Metadata,
			}
			if opts.OrganizationHooks != nil && opts.OrganizationHooks.BeforeCreateOrganization != nil {
				updated, err := opts.OrganizationHooks.BeforeCreateOrganization(c.R.Context(), OrganizationCreateHookData{
					Organization: createData,
					User:         *user,
				})
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
				if updated != nil {
					createData = *updated
				}
			}
			if createData.Name == "" || createData.Slug == "" {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
				return
			}
			slug := strings.ToLower(createData.Slug)
			if !slugPattern.MatchString(slug) {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidSlug))
				return
			}
			now := time.Now()
			orgID, err := id.Generate(32)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
			org := &types.Organization{ID: orgID, Name: createData.Name, Slug: slug, Logo: createData.Logo, Metadata: createData.Metadata, CreatedAt: now}
			if err := ext.CreateOrganization(c.R.Context(), org); err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeSlugExists))
				return
			}
			memberID, err := id.Generate(32)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
			memberData, err := runBeforeAddMemberHook(c.R.Context(), opts, OrganizationMemberCreateData{
				UserID:         user.ID,
				OrganizationID: orgID,
				Role:           organizationCreatorRole(opts),
			}, user, org)
			if err != nil {
				_ = ext.DeleteOrganization(c.R.Context(), orgID)
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			member := &types.Member{
				ID:             memberID,
				OrganizationID: memberData.OrganizationID,
				UserID:         memberData.UserID,
				Role:           memberData.Role,
				CreatedAt:      now,
			}
			if err := ext.CreateMember(c.R.Context(), member); err != nil {
				_ = ext.DeleteOrganization(c.R.Context(), orgID)
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			if err := runAfterAddMemberHook(c.R.Context(), opts, member, user, org); err != nil {
				_ = ext.DeleteMember(c.R.Context(), member.ID)
				_ = ext.DeleteOrganization(c.R.Context(), orgID)
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
			defaultTeamID, err := createDefaultOrganizationTeam(c.R.Context(), ext, opts, org, user, now)
			if err != nil {
				_ = ext.DeleteMember(c.R.Context(), member.ID)
				_ = ext.DeleteOrganization(c.R.Context(), orgID)
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			if opts.OrganizationHooks != nil && opts.OrganizationHooks.AfterCreateOrganization != nil {
				if err := opts.OrganizationHooks.AfterCreateOrganization(c.R.Context(), OrganizationCreatedHookData{
					Organization: *org,
					Member:       *member,
					User:         *user,
				}); err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
			}
			if !body.KeepCurrentActiveOrganization {
				sessionUpdate := map[string]any{
					constants.SessionActiveOrganizationID: orgID,
				}
				if defaultTeamID != "" {
					sessionUpdate[constants.SessionActiveTeamID] = defaultTeamID
				}
				_, _ = c.Auth.SetSessionAdditional(c.R.Context(), sess.Token, sessionUpdate)
			}
			c.WriteJSON(http.StatusOK, organizationCreateResponse(org, []types.Member{*member}))
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
			sess, user, ok := c.RequireSession()
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
				Data           struct {
					Name     string  `json:"name"`
					Slug     string  `json:"slug"`
					Logo     *string `json:"logo"`
					Metadata string  `json:"-"`
				} `json:"data"`
				Metadata string `json:"-"`
			}
			var raw map[string]json.RawMessage
			if err := c.ParseJSON(&raw); err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			if err := decodeOrganizationUpdateBody(raw, &body); err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			orgID := organizationIDFromRequest(sess, body.OrganizationID)
			if orgID == "" {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
				return
			}
			member, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
				return
			}
			if !organizationMemberHasPermissions(c.R.Context(), ext, opts, orgID, member.Role, map[string][]string{"organization": []string{"update"}}) {
				c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
				return
			}
			name := body.Data.Name
			if name == "" {
				name = body.Name
			}
			slug := body.Data.Slug
			if slug == "" {
				slug = body.Slug
			}
			logo := body.Data.Logo
			if logo == nil {
				logo = body.Logo
			}
			var metadata *string
			if body.Data.Metadata != "" {
				metadata = &body.Data.Metadata
			} else if body.Metadata != "" {
				metadata = &body.Metadata
			}
			updateData := OrganizationUpdateData{
				Name:     name,
				Slug:     slug,
				Logo:     logo,
				Metadata: metadata,
			}
			if opts.OrganizationHooks != nil && opts.OrganizationHooks.BeforeUpdateOrganization != nil {
				updated, err := opts.OrganizationHooks.BeforeUpdateOrganization(c.R.Context(), OrganizationUpdateHookData{
					Organization: updateData,
					User:         *user,
					Member:       *member,
				})
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
				if updated != nil {
					updateData = *updated
				}
			}
			name = updateData.Name
			slug = updateData.Slug
			logo = updateData.Logo
			metadata = updateData.Metadata
			if slug != "" {
				slug = strings.ToLower(slug)
				if !slugPattern.MatchString(slug) {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidSlug))
					return
				}
			}
			org, err := ext.UpdateOrganization(c.R.Context(), orgID, name, slug, logo, metadata)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeOrgNotFound))
				return
			}
			if opts.OrganizationHooks != nil && opts.OrganizationHooks.AfterUpdateOrganization != nil {
				if err := opts.OrganizationHooks.AfterUpdateOrganization(c.R.Context(), OrganizationUpdatedHookData{
					Organization: *org,
					User:         *user,
					Member:       *member,
				}); err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
			}
			c.WriteJSON(http.StatusOK, organizationBaseResponse(org))
		}),
		rt(http.MethodPost, "/organization/delete", func(c *auth.Context) {
			if opts.DisableOrganizationDeletion {
				c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeOrgNotFound))
				return
			}
			sess, user, ok := c.RequireSession()
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
			if err := c.ParseJSON(&body); err != nil || body.OrganizationID == "" {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			member, err := ext.FindMemberByOrgAndUser(c.R.Context(), body.OrganizationID, user.ID)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
				return
			}
			if !organizationMemberHasPermissions(c.R.Context(), ext, opts, body.OrganizationID, member.Role, map[string][]string{"organization": []string{"delete"}}) {
				c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
				return
			}
			org, err := ext.FindOrganizationByID(c.R.Context(), body.OrganizationID)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
				return
			}
			deleteHookData := OrganizationDeleteHookData{
				Organization: *org,
				User:         *user,
			}
			if opts.OrganizationHooks != nil && opts.OrganizationHooks.BeforeDeleteOrganization != nil {
				if err := opts.OrganizationHooks.BeforeDeleteOrganization(c.R.Context(), deleteHookData); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
			}
			if activeOrgID, exists := auth.SessionAdditional(sess, constants.SessionActiveOrganizationID); exists && activeOrgID == body.OrganizationID {
				_, _ = c.Auth.SetSessionAdditional(c.R.Context(), sess.Token, map[string]any{constants.SessionActiveOrganizationID: nil})
			}
			if err := ext.DeleteOrganization(c.R.Context(), body.OrganizationID); err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
				return
			}
			if opts.OrganizationHooks != nil && opts.OrganizationHooks.AfterDeleteOrganization != nil {
				if err := opts.OrganizationHooks.AfterDeleteOrganization(c.R.Context(), deleteHookData); err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
			}
			c.WriteJSON(http.StatusOK, organizationBaseResponse(org))
		}),
		rt(http.MethodGet, "/organization/get-full-organization", func(c *auth.Context) {
			sess, user, ok := c.RequireSession()
			if !ok {
				return
			}
			ext, ok := requireExt(c)
			if !ok {
				return
			}
			query := c.R.URL.Query()
			orgID := organizationIDFromRequest(sess, query.Get("organizationId"))
			if slug := query.Get("organizationSlug"); slug != "" {
				org, err := ext.FindOrganizationBySlug(c.R.Context(), slug)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
					return
				}
				orgID = org.ID
			}
			if orgID == "" {
				c.WriteNull()
				return
			}
			org, err := ext.FindOrganizationByID(c.R.Context(), orgID)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeOrgNotFound))
				return
			}
			if _, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID); err != nil {
				c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
				return
			}
			members, _ := ext.ListMembersByOrg(c.R.Context(), orgID)
			members, err = limitFullOrganizationMembers(members, query.Get("membersLimit"), opts.MembershipLimit)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			invitations, _ := ext.ListInvitationsByOrg(c.R.Context(), orgID)
			var teams []types.Team
			if organizationTeamsEnabled(opts) {
				teams, _ = ext.ListTeamsByOrg(c.R.Context(), orgID)
			}
			c.WriteJSON(http.StatusOK, organizationResponse(org, members, invitations, teams, organizationTeamsEnabled(opts)))
		}),
		rt(http.MethodPost, "/organization/set-active", func(c *auth.Context) {
			sess, user, ok := c.RequireSession()
			if !ok {
				return
			}
			ext, ok := requireExt(c)
			if !ok {
				return
			}
			var raw map[string]json.RawMessage
			if err := c.ParseJSON(&raw); err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			organizationID, hasOrganizationID, organizationIDIsNull, err := stringFieldFromRaw(raw, "organizationId")
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			organizationSlug, _, _, err := stringFieldFromRaw(raw, "organizationSlug")
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			if hasOrganizationID && organizationIDIsNull {
				_, _ = c.Auth.SetSessionAdditional(c.R.Context(), sess.Token, map[string]any{constants.SessionActiveOrganizationID: nil})
				c.WriteNull()
				return
			}
			orgID := organizationID
			if orgID == "" && organizationSlug != "" {
				org, err := ext.FindOrganizationBySlug(c.R.Context(), organizationSlug)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
					return
				}
				orgID = org.ID
			}
			if orgID == "" {
				if activeOrgID, exists := auth.SessionAdditional(sess, constants.SessionActiveOrganizationID); exists {
					orgID, _ = activeOrgID.(string)
				}
			}
			if orgID == "" {
				c.WriteNull()
				return
			}
			if _, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID); err != nil {
				_, _ = c.Auth.SetSessionAdditional(c.R.Context(), sess.Token, map[string]any{constants.SessionActiveOrganizationID: nil})
				c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
				return
			}
			org, err := ext.FindOrganizationByID(c.R.Context(), orgID)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
				return
			}
			_, _ = c.Auth.SetSessionAdditional(c.R.Context(), sess.Token, map[string]any{
				constants.SessionActiveOrganizationID: orgID,
			})
			c.WriteJSON(http.StatusOK, organizationBaseResponse(org))
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
		rt(http.MethodPost, "/organization/invite-member", inviteMemberHandler(opts)),
		rt(http.MethodPost, "/organization/accept-invitation", acceptInvitationHandler(opts)),
		rt(http.MethodPost, "/organization/reject-invitation", rejectInvitationHandler(opts)),
		rt(http.MethodPost, "/organization/cancel-invitation", cancelInvitationHandler(opts)),
		rt(http.MethodGet, "/organization/get-invitation", getInvitationHandler(opts)),
		rt(http.MethodGet, "/organization/list-invitations", listOrgInvitationsHandler()),
		rt(http.MethodGet, "/organization/list-user-invitations", listUserInvitationsHandler()),
		srt(http.MethodPost, "/organization/add-member", addMemberHandler(opts)),
		rt(http.MethodPost, "/organization/remove-member", removeMemberHandler(opts)),
		rt(http.MethodPost, "/organization/update-member-role", updateMemberRoleHandler(opts)),
		rt(http.MethodGet, "/organization/get-active-member", getActiveMemberHandler()),
		rt(http.MethodPost, "/organization/leave", leaveOrgHandler(opts)),
		rt(http.MethodGet, "/organization/list-members", listMembersHandler()),
		rt(http.MethodGet, "/organization/get-active-member-role", getActiveMemberRoleHandler()),
		rt(http.MethodPost, "/organization/has-permission", hasOrgPermissionHandler(opts)),
	}
	if organizationTeamsEnabled(opts) {
		routes = append(routes,
			rt(http.MethodPost, "/organization/create-team", createTeamHandler(opts)),
			rt(http.MethodPost, "/organization/remove-team", removeTeamHandler(opts)),
			rt(http.MethodPost, "/organization/update-team", updateTeamHandler(opts)),
			rt(http.MethodGet, "/organization/list-teams", listTeamsHandler()),
			rt(http.MethodPost, "/organization/set-active-team", setActiveTeamHandler()),
			rt(http.MethodGet, "/organization/list-user-teams", listUserTeamsHandler()),
			rt(http.MethodGet, "/organization/list-team-members", listTeamMembersHandler()),
			rt(http.MethodPost, "/organization/add-team-member", addTeamMemberHandler(opts)),
			rt(http.MethodPost, "/organization/remove-team-member", removeTeamMemberHandler(opts)),
		)
	}
	if organizationDynamicAccessControlEnabled(opts) {
		routes = append(routes,
			rt(http.MethodPost, "/organization/create-role", createOrgRoleHandler(opts)),
			rt(http.MethodPost, "/organization/update-role", updateOrgRoleHandler(opts)),
			rt(http.MethodPost, "/organization/delete-role", deleteOrgRoleHandler(opts)),
			rt(http.MethodGet, "/organization/list-roles", listOrgRolesHandler(opts)),
			rt(http.MethodGet, "/organization/get-role", getOrgRoleHandler(opts)),
		)
	}
	schemaIDs := []string{constants.PluginOrganization}
	if organizationTeamsEnabled(opts) {
		schemaIDs = append(schemaIDs, constants.PluginOrganizationTeams)
	}
	if organizationDynamicAccessControlEnabled(opts) {
		schemaIDs = append(schemaIDs, constants.PluginOrganizationRoles)
	}
	return basePlugin{id: constants.PluginOrganization, routes: routes, schemaIDs: schemaIDs}
}

func organizationTeamsEnabled(opts OrganizationOptions) bool {
	return opts.Teams != nil && opts.Teams.Enabled
}

func organizationDynamicAccessControlEnabled(opts OrganizationOptions) bool {
	return opts.DynamicAccessControl != nil && opts.DynamicAccessControl.Enabled
}

func organizationMaximumRoles(ctx context.Context, opts OrganizationOptions, organizationID string) (int, error) {
	if !organizationDynamicAccessControlEnabled(opts) {
		return 0, nil
	}
	if opts.DynamicAccessControl.MaximumRolesPerOrganizationFunc != nil {
		return opts.DynamicAccessControl.MaximumRolesPerOrganizationFunc(ctx, organizationID)
	}
	return opts.DynamicAccessControl.MaximumRolesPerOrganization, nil
}

func organizationDefaultTeamEnabled(opts OrganizationOptions) bool {
	if !organizationTeamsEnabled(opts) {
		return false
	}
	if opts.Teams.DefaultTeam == nil || opts.Teams.DefaultTeam.Enabled == nil {
		return true
	}
	return *opts.Teams.DefaultTeam.Enabled
}

func organizationMaximumTeams(ctx context.Context, opts OrganizationOptions, data OrganizationMaximumTeamsData) (int, error) {
	if !organizationTeamsEnabled(opts) {
		return 0, nil
	}
	if opts.Teams.MaximumTeamsFunc != nil {
		return opts.Teams.MaximumTeamsFunc(ctx, data)
	}
	return opts.Teams.MaximumTeams, nil
}

func organizationMaximumMembersPerTeam(ctx context.Context, opts OrganizationOptions, data OrganizationMaximumMembersPerTeamData) (int, error) {
	if !organizationTeamsEnabled(opts) {
		return 0, nil
	}
	if opts.Teams.MaximumMembersPerTeamFunc != nil {
		if data.Session == nil || data.User == nil {
			return 0, stderrors.New("maximum members per team callback requires a session")
		}
		return opts.Teams.MaximumMembersPerTeamFunc(ctx, data)
	}
	return opts.Teams.MaximumMembersPerTeam, nil
}

func organizationAllowRemovingAllTeams(opts OrganizationOptions) bool {
	if !organizationTeamsEnabled(opts) {
		return false
	}
	return opts.Teams.AllowRemovingAllTeams
}

func organizationCreationAllowed(ctx context.Context, opts OrganizationOptions, user *types.User) (bool, error) {
	if opts.AllowUserToCreateOrganizationFunc != nil {
		return opts.AllowUserToCreateOrganizationFunc(ctx, *user)
	}
	if opts.AllowUserToCreateOrganization == nil {
		return true, nil
	}
	return *opts.AllowUserToCreateOrganization, nil
}

func organizationCreatorRole(opts OrganizationOptions) string {
	if opts.CreatorRole == "" {
		return constants.RoleOwner
	}
	return opts.CreatorRole
}

func organizationLimitReached(ctx context.Context, ext store.ExtStore, opts OrganizationOptions, user *types.User) (bool, error) {
	if opts.OrganizationLimitReached != nil {
		return opts.OrganizationLimitReached(ctx, *user)
	}
	if opts.OrganizationLimit <= 0 {
		return false, nil
	}
	members, err := ext.ListMembersByUser(ctx, user.ID)
	if err != nil {
		return false, err
	}
	return len(members) >= opts.OrganizationLimit, nil
}

func organizationMembershipLimitReached(ctx context.Context, ext store.ExtStore, opts OrganizationOptions, user *types.User, organization *types.Organization) (bool, error) {
	effectiveLimit := opts.MembershipLimit
	if opts.MembershipLimitFunc != nil {
		limit, err := opts.MembershipLimitFunc(ctx, *user, *organization)
		if err != nil {
			return false, err
		}
		effectiveLimit = limit
	}
	if effectiveLimit <= 0 {
		effectiveLimit = 100
	}
	members, err := ext.ListMembersByOrg(ctx, organization.ID)
	if err != nil {
		return false, err
	}
	return len(members) >= effectiveLimit, nil
}

func organizationInvitationExpiresIn(opts OrganizationOptions) time.Duration {
	if opts.InvitationExpiresIn <= 0 {
		return 48 * time.Hour
	}
	return opts.InvitationExpiresIn
}

func organizationInvitationLimit(ctx context.Context, opts OrganizationOptions, data OrganizationInvitationLimitData) (int, error) {
	if opts.InvitationLimitFunc != nil {
		return opts.InvitationLimitFunc(ctx, data)
	}
	if opts.InvitationLimit <= 0 {
		return 100, nil
	}
	return opts.InvitationLimit, nil
}

func organizationRequireEmailVerificationOnInvitation(opts OrganizationOptions) bool {
	return opts.RequireEmailVerificationOnInvitation != nil && *opts.RequireEmailVerificationOnInvitation
}

func organizationInvitationLimitReached(ctx context.Context, ext store.ExtStore, organizationID string, limit int) (bool, error) {
	invitations, err := ext.ListInvitationsByOrg(ctx, organizationID)
	if err != nil {
		return false, err
	}
	now := time.Now()
	pending := 0
	for _, invitation := range invitations {
		if invitation.Status == constants.InvitationPending && now.Before(invitation.ExpiresAt) {
			pending++
		}
	}
	return pending >= limit, nil
}

func sendOrganizationInvitationEmail(ctx context.Context, opts OrganizationOptions, req *http.Request, organization *types.Organization, invitation *types.Invitation, inviter *types.Member, inviterUser *types.User) error {
	if opts.SendInvitationEmail == nil {
		return nil
	}
	return opts.SendInvitationEmail(ctx, OrganizationInvitationEmailData{
		ID:           invitation.ID,
		Role:         invitation.Role,
		Email:        strings.ToLower(invitation.Email),
		Organization: *organization,
		Invitation:   *invitation,
		Inviter:      *inviter,
		InviterUser:  *inviterUser,
		Request:      req,
	})
}

func runBeforeAddMemberHook(ctx context.Context, opts OrganizationOptions, member OrganizationMemberCreateData, user *types.User, organization *types.Organization) (OrganizationMemberCreateData, error) {
	if opts.OrganizationHooks == nil || opts.OrganizationHooks.BeforeAddMember == nil {
		return member, nil
	}
	updated, err := opts.OrganizationHooks.BeforeAddMember(ctx, OrganizationMemberAddHookData{
		Member:       member,
		User:         *user,
		Organization: *organization,
	})
	if err != nil {
		return member, err
	}
	if updated == nil {
		return member, nil
	}
	return *updated, nil
}

func runAfterAddMemberHook(ctx context.Context, opts OrganizationOptions, member *types.Member, user *types.User, organization *types.Organization) error {
	if opts.OrganizationHooks == nil || opts.OrganizationHooks.AfterAddMember == nil {
		return nil
	}
	return opts.OrganizationHooks.AfterAddMember(ctx, OrganizationMemberHookData{
		Member:       *member,
		User:         *user,
		Organization: *organization,
	})
}

func runMemberHookData(ctx context.Context, c *auth.Context, ext store.ExtStore, member *types.Member) (*types.User, *types.Organization, bool) {
	user, err := c.Auth.Store().FindUserByID(ctx, member.UserID)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
		return nil, nil, false
	}
	organization, err := ext.FindOrganizationByID(ctx, member.OrganizationID)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
		return nil, nil, false
	}
	return user, organization, true
}

func createDefaultOrganizationTeam(ctx context.Context, ext store.ExtStore, opts OrganizationOptions, org *types.Organization, user *types.User, now time.Time) (string, error) {
	if !organizationDefaultTeamEnabled(opts) {
		return "", nil
	}
	teamID, err := id.Generate(32)
	if err != nil {
		return "", err
	}
	teamData := OrganizationTeamCreateData{Name: org.Name, OrganizationID: org.ID}
	if opts.OrganizationHooks != nil && opts.OrganizationHooks.BeforeCreateTeam != nil {
		updated, err := opts.OrganizationHooks.BeforeCreateTeam(ctx, OrganizationTeamCreateHookData{
			Team:         teamData,
			User:         user,
			Organization: *org,
		})
		if err != nil {
			return "", err
		}
		if updated != nil {
			teamData = *updated
		}
	}
	team := &types.Team{
		ID:             teamID,
		Name:           teamData.Name,
		OrganizationID: teamData.OrganizationID,
		CreatedAt:      now,
	}
	teamCreated := false
	if opts.Teams != nil && opts.Teams.DefaultTeam != nil && opts.Teams.DefaultTeam.CustomCreateDefaultTeam != nil {
		customTeam, err := opts.Teams.DefaultTeam.CustomCreateDefaultTeam(ctx, *org, *user)
		if err != nil {
			return "", err
		}
		if customTeam != nil {
			if customTeam.ID == "" {
				return "", stderrors.New("custom default team must include an id")
			}
			if customTeam.OrganizationID != org.ID {
				return "", stderrors.New("custom default team must belong to the organization")
			}
			team = customTeam
			teamID = customTeam.ID
			teamCreated = true
		}
	}
	if !teamCreated {
		if err := ext.CreateTeam(ctx, team); err != nil {
			return "", err
		}
	}
	teamMemberID, err := id.Generate(32)
	if err != nil {
		_ = ext.DeleteTeam(ctx, teamID)
		return "", err
	}
	if err := ext.CreateTeamMember(ctx, &types.TeamMember{
		ID:        teamMemberID,
		TeamID:    team.ID,
		UserID:    user.ID,
		CreatedAt: now,
	}); err != nil {
		_ = ext.DeleteTeam(ctx, teamID)
		return "", err
	}
	if opts.OrganizationHooks != nil && opts.OrganizationHooks.AfterCreateTeam != nil {
		if err := opts.OrganizationHooks.AfterCreateTeam(ctx, OrganizationTeamHookData{
			Team:         *team,
			User:         user,
			Organization: *org,
		}); err != nil {
			_ = ext.DeleteTeam(ctx, teamID)
			return "", err
		}
	}
	return team.ID, nil
}

func teamMemberLimitReached(ctx context.Context, ext store.ExtStore, opts OrganizationOptions, teamID string, userID string, organizationID string, sess *types.Session, currentUser *types.User) (bool, error) {
	limit, err := organizationMaximumMembersPerTeam(ctx, opts, OrganizationMaximumMembersPerTeamData{
		TeamID:         teamID,
		OrganizationID: organizationID,
		Session:        sess,
		User:           currentUser,
	})
	if err != nil {
		return false, err
	}
	if limit <= 0 {
		return false, nil
	}
	if userID != "" {
		if _, err := ext.FindTeamMember(ctx, teamID, userID); err == nil {
			return false, nil
		}
	}
	members, err := ext.ListTeamMembers(ctx, teamID)
	if err != nil {
		return false, err
	}
	return len(members) >= limit, nil
}

func anyTeamMemberLimitReached(ctx context.Context, ext store.ExtStore, opts OrganizationOptions, teamIDs []string, userID string, organizationID string, sess *types.Session, currentUser *types.User) (bool, error) {
	for _, teamID := range teamIDs {
		reached, err := teamMemberLimitReached(ctx, ext, opts, teamID, userID, organizationID, sess, currentUser)
		if err != nil || reached {
			return reached, err
		}
	}
	return false, nil
}

func organizationCreateResponse(org *types.Organization, members []types.Member) map[string]any {
	out := organizationBaseResponse(org)
	out["members"] = members
	return out
}

func organizationResponse(org *types.Organization, members []types.Member, invitations []types.Invitation, teams []types.Team, includeTeams bool) map[string]any {
	out := organizationBaseResponse(org)
	out["members"] = members
	out["invitations"] = invitations
	if includeTeams {
		out["teams"] = teams
	}
	return out
}

func organizationBaseResponse(org *types.Organization) map[string]any {
	out := map[string]any{
		"id":        org.ID,
		"name":      org.Name,
		"slug":      org.Slug,
		"logo":      org.Logo,
		"metadata":  organizationMetadataValue(org.Metadata),
		"createdAt": org.CreatedAt,
	}
	if org.UpdatedAt != nil {
		out["updatedAt"] = *org.UpdatedAt
	}
	return out
}

func organizationMetadataValue(metadata string) any {
	if metadata == "" {
		return nil
	}
	var out any
	if err := json.Unmarshal([]byte(metadata), &out); err == nil {
		return out
	}
	return metadata
}

func decodeOrganizationCreateBody(raw map[string]json.RawMessage, body *struct {
	Name                          string `json:"name"`
	Slug                          string `json:"slug"`
	Logo                          string `json:"logo"`
	Metadata                      string `json:"-"`
	KeepCurrentActiveOrganization bool   `json:"keepCurrentActiveOrganization"`
}) error {
	payload, err := marshalRaw(raw)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payload, body); err != nil {
		return err
	}
	metadata, _, err := metadataStringFromRaw(raw, "metadata")
	if err != nil {
		return err
	}
	body.Metadata = metadata
	return nil
}

func decodeOrganizationUpdateBody(raw map[string]json.RawMessage, body *struct {
	OrganizationID string  `json:"organizationId"`
	Name           string  `json:"name"`
	Slug           string  `json:"slug"`
	Logo           *string `json:"logo"`
	Data           struct {
		Name     string  `json:"name"`
		Slug     string  `json:"slug"`
		Logo     *string `json:"logo"`
		Metadata string  `json:"-"`
	} `json:"data"`
	Metadata string `json:"-"`
}) error {
	payload, err := marshalRaw(raw)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payload, body); err != nil {
		return err
	}
	metadata, ok, err := metadataStringFromRaw(raw, "metadata")
	if err != nil {
		return err
	}
	if ok {
		body.Metadata = metadata
	}
	if dataRaw, exists := raw["data"]; exists && string(dataRaw) != "null" {
		var data map[string]json.RawMessage
		if err := json.Unmarshal(dataRaw, &data); err != nil {
			return err
		}
		metadata, ok, err := metadataStringFromRaw(data, "metadata")
		if err != nil {
			return err
		}
		if ok {
			body.Data.Metadata = metadata
		}
	}
	return nil
}

func metadataStringFromRaw(raw map[string]json.RawMessage, key string) (string, bool, error) {
	value, ok := raw[key]
	if !ok {
		return "", false, nil
	}
	if string(value) == "null" {
		return "", true, nil
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, value); err != nil {
		return "", true, err
	}
	return compact.String(), true, nil
}

func marshalRaw(raw map[string]json.RawMessage) ([]byte, error) {
	return json.Marshal(raw)
}

func limitFullOrganizationMembers(members []types.Member, limitValue string, configuredLimit int) ([]types.Member, error) {
	limit := configuredLimit
	if limitValue != "" {
		parsed, _, err := parseMemberPaginationValue(limitValue)
		if err != nil {
			return nil, err
		}
		limit = parsed
	}
	if limit <= 0 {
		limit = 100
	}
	if len(members) <= limit {
		return members, nil
	}
	return members[:limit], nil
}

func stringFieldFromRaw(raw map[string]json.RawMessage, key string) (string, bool, bool, error) {
	value, ok := raw[key]
	if !ok {
		return "", false, false, nil
	}
	if string(value) == "null" {
		return "", true, true, nil
	}
	var out string
	if err := json.Unmarshal(value, &out); err != nil {
		return "", true, false, err
	}
	return out, true, false, nil
}

func inviteMemberHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			OrganizationID string          `json:"organizationId"`
			Email          string          `json:"email"`
			Role           json.RawMessage `json:"role"`
			Resend         bool            `json:"resend"`
			TeamID         json.RawMessage `json:"teamId"`
		}
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		orgID := organizationIDFromRequest(sess, body.OrganizationID)
		email := auth.NormalizeEmail(body.Email)
		role, ok := parseMemberRole(body.Role)
		if orgID == "" || !ok || !internalcrypto.ValidateEmail(email) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		member, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID)
		if err != nil || !organizationMemberHasPermissions(c.R.Context(), ext, opts, orgID, member.Role, map[string][]string{"invitation": []string{"create"}}) {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		roleExists, err := organizationRoleExists(c.R.Context(), ext, opts, orgID, role)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if !roleExists {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		creatorRole := organizationCreatorRole(opts)
		if memberHasRole(role, creatorRole) && !memberHasRole(member.Role, creatorRole) {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		org, err := ext.FindOrganizationByID(c.R.Context(), orgID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		if invitationEmailIsMember(c, ext, orgID, email) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		pending, hasPending := pendingInvitationForEmailOrg(c, ext, orgID, email)
		if hasPending {
			if body.Resend {
				expiresAt := time.Now().Add(organizationInvitationExpiresIn(opts))
				if err := ext.UpdateInvitationExpiresAt(c.R.Context(), pending.ID, expiresAt); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
				pending.ExpiresAt = expiresAt
				if err := sendOrganizationInvitationEmail(c.R.Context(), opts, c.R, org, pending, member, user); err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				c.WriteJSON(http.StatusOK, pending)
				return
			}
			if opts.CancelPendingInvitationsOnReInvite {
				if err := ext.UpdateInvitationStatus(c.R.Context(), pending.ID, constants.InvitationCanceled); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
			} else {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
		}
		invitationLimit, err := organizationInvitationLimit(c.R.Context(), opts, OrganizationInvitationLimitData{
			User:         *user,
			Organization: *org,
			Member:       *member,
		})
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		limitReached, err := organizationInvitationLimitReached(c.R.Context(), ext, orgID, invitationLimit)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if limitReached {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		teamIDs, err := parseInvitationTeamIDs(body.TeamID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if len(teamIDs) > 0 && !organizationTeamsEnabled(opts) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if !invitationTeamsBelongToOrg(c, ext, orgID, teamIDs) {
			return
		}
		teamLimitReached, err := anyTeamMemberLimitReached(c.R.Context(), ext, opts, teamIDs, "", orgID, sess, user)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if teamLimitReached {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		now := time.Now()
		invID, err := id.Generate(32)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		inv := &types.Invitation{
			ID: invID, OrganizationID: orgID, Email: email, Role: role,
			Status: constants.InvitationPending, InviterID: user.ID, TeamID: strings.Join(teamIDs, ","),
			ExpiresAt: now.Add(organizationInvitationExpiresIn(opts)), CreatedAt: now,
		}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.BeforeCreateInvitation != nil {
			updated, err := opts.OrganizationHooks.BeforeCreateInvitation(c.R.Context(), OrganizationInvitationCreateHookData{
				Invitation: OrganizationInvitationCreateData{
					Email:          inv.Email,
					Role:           inv.Role,
					OrganizationID: inv.OrganizationID,
					InviterID:      inv.InviterID,
					TeamID:         inv.TeamID,
					ExpiresAt:      inv.ExpiresAt,
				},
				Inviter:      *user,
				Organization: *org,
			})
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			if updated != nil {
				inv.Email = auth.NormalizeEmail(updated.Email)
				inv.Role = updated.Role
				inv.OrganizationID = updated.OrganizationID
				inv.InviterID = updated.InviterID
				inv.TeamID = updated.TeamID
				if !updated.ExpiresAt.IsZero() {
					inv.ExpiresAt = updated.ExpiresAt
				}
			}
		}
		if err := ext.CreateInvitation(c.R.Context(), inv); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if err := sendOrganizationInvitationEmail(c.R.Context(), opts, c.R, org, inv, member, user); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.AfterCreateInvitation != nil {
			if err := opts.OrganizationHooks.AfterCreateInvitation(c.R.Context(), OrganizationInvitationHookData{
				Invitation:   *inv,
				Inviter:      *user,
				Organization: *org,
			}); err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
		}
		c.WriteJSON(http.StatusOK, inv)
	}
}

func invitationEmailIsMember(c *auth.Context, ext store.ExtStore, organizationID string, email string) bool {
	user, err := c.Auth.Store().FindUserByEmail(c.R.Context(), email)
	if err != nil {
		return false
	}
	_, err = ext.FindMemberByOrgAndUser(c.R.Context(), organizationID, user.ID)
	return err == nil
}

func pendingInvitationForEmailOrg(c *auth.Context, ext store.ExtStore, organizationID string, email string) (*types.Invitation, bool) {
	invitations, err := ext.ListInvitationsByEmail(c.R.Context(), email)
	if err != nil {
		return nil, false
	}
	now := time.Now()
	for _, invitation := range invitations {
		if invitation.OrganizationID == organizationID && invitation.Status == constants.InvitationPending && now.Before(invitation.ExpiresAt) {
			inv := invitation
			return &inv, true
		}
	}
	return nil, false
}

func parseInvitationTeamIDs(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err == nil {
		return normalizeInvitationTeamIDs([]string{value})
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err == nil {
		return normalizeInvitationTeamIDs(values)
	}
	return nil, apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest)
}

func normalizeInvitationTeamIDs(values []string) ([]string, error) {
	teamIDs := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.Contains(value, ",") {
			return nil, apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		teamIDs = append(teamIDs, value)
	}
	return teamIDs, nil
}

func invitationTeamsBelongToOrg(c *auth.Context, ext store.ExtStore, organizationID string, teamIDs []string) bool {
	for _, teamID := range teamIDs {
		team, err := ext.FindTeamByID(c.R.Context(), teamID)
		if err != nil || team.OrganizationID != organizationID {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return false
		}
	}
	return true
}

func acceptInvitationHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
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
		if err := c.ParseJSON(&body); err != nil || body.InvitationID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		inv, err := ext.FindInvitationByID(c.R.Context(), body.InvitationID)
		if err != nil || inv.Status != constants.InvitationPending || !time.Now().Before(inv.ExpiresAt) {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeInvitationNotFound))
			return
		}
		if !strings.EqualFold(inv.Email, user.Email) {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		if !requireVerifiedInvitationEmail(c, opts, user) {
			return
		}
		org, err := ext.FindOrganizationByID(c.R.Context(), inv.OrganizationID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		if _, err := ext.FindMemberByOrgAndUser(c.R.Context(), inv.OrganizationID, user.ID); err == nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		limitReached, err := organizationMembershipLimitReached(c.R.Context(), ext, opts, user, org)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if limitReached {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		teamIDs := invitationTeamIDs(inv.TeamID)
		if len(teamIDs) > 0 && !organizationTeamsEnabled(opts) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if !invitationTeamsBelongToOrg(c, ext, inv.OrganizationID, teamIDs) {
			return
		}
		teamLimitReached, err := anyTeamMemberLimitReached(c.R.Context(), ext, opts, teamIDs, user.ID, inv.OrganizationID, sess, user)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if teamLimitReached {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.BeforeAcceptInvitation != nil {
			if err := opts.OrganizationHooks.BeforeAcceptInvitation(c.R.Context(), OrganizationInvitationUserHookData{
				Invitation:   *inv,
				User:         *user,
				Organization: *org,
			}); err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
		}
		now := time.Now()
		memberID, err := id.Generate(32)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		member := &types.Member{
			ID: memberID, OrganizationID: inv.OrganizationID, UserID: user.ID,
			Role: inv.Role, CreatedAt: now,
		}
		if err := ext.UpdateInvitationStatus(c.R.Context(), inv.ID, constants.InvitationAccepted); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvitationNotFound))
			return
		}
		if err := ext.CreateMember(c.R.Context(), member); err != nil {
			_ = ext.UpdateInvitationStatus(c.R.Context(), inv.ID, constants.InvitationPending)
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if err := createInvitationTeamMemberships(c, ext, teamIDs, user.ID); err != nil {
			_ = ext.DeleteMember(c.R.Context(), member.ID)
			_ = ext.UpdateInvitationStatus(c.R.Context(), inv.ID, constants.InvitationPending)
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		sessionUpdate := map[string]any{constants.SessionActiveOrganizationID: inv.OrganizationID}
		if len(teamIDs) == 1 {
			sessionUpdate[constants.SessionActiveTeamID] = teamIDs[0]
		}
		_, _ = c.Auth.SetSessionAdditional(c.R.Context(), sess.Token, sessionUpdate)
		inv.Status = constants.InvitationAccepted
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.AfterAcceptInvitation != nil {
			if err := opts.OrganizationHooks.AfterAcceptInvitation(c.R.Context(), OrganizationInvitationAcceptHookData{
				Invitation:   *inv,
				Member:       *member,
				User:         *user,
				Organization: *org,
			}); err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
		}
		c.WriteJSON(http.StatusOK, map[string]any{"invitation": inv, "member": member})
	}
}

func invitationTeamIDs(value string) []string {
	if value == "" {
		return nil
	}
	ids := strings.Split(value, ",")
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" {
			out = append(out, id)
		}
	}
	return out
}

func createInvitationTeamMemberships(c *auth.Context, ext store.ExtStore, teamIDs []string, userID string) error {
	now := time.Now()
	for _, teamID := range teamIDs {
		if _, err := ext.FindTeamMember(c.R.Context(), teamID, userID); err == nil {
			continue
		}
		teamMemberID, err := id.Generate(32)
		if err != nil {
			return err
		}
		if err := ext.CreateTeamMember(c.R.Context(), &types.TeamMember{
			ID: teamMemberID, TeamID: teamID, UserID: userID, CreatedAt: now,
		}); err != nil {
			return err
		}
	}
	return nil
}

func findPendingRecipientInvitation(c *auth.Context, ext store.ExtStore, invitationID string, email string) (*types.Invitation, bool) {
	inv, err := ext.FindInvitationByID(c.R.Context(), invitationID)
	if err != nil || inv.Status != constants.InvitationPending || !time.Now().Before(inv.ExpiresAt) {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvitationNotFound))
		return nil, false
	}
	if !strings.EqualFold(inv.Email, email) {
		c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
		return nil, false
	}
	return inv, true
}

func requireVerifiedInvitationEmail(c *auth.Context, opts OrganizationOptions, user *types.User) bool {
	if organizationRequireEmailVerificationOnInvitation(opts) && !user.EmailVerified {
		c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
		return false
	}
	return true
}

func requireVerifiedEmailForInvitationList(c *auth.Context, user *types.User) bool {
	if !user.EmailVerified {
		c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
		return false
	}
	return true
}

func invitationResponse(c *auth.Context, inv *types.Invitation, org *types.Organization) map[string]any {
	inviterEmail := ""
	if inviter, err := c.Auth.Store().FindUserByID(c.R.Context(), inv.InviterID); err == nil {
		inviterEmail = inviter.Email
	}
	return map[string]any{
		"id":               inv.ID,
		"email":            inv.Email,
		"role":             inv.Role,
		"organizationId":   inv.OrganizationID,
		"organizationName": org.Name,
		"organizationSlug": org.Slug,
		"inviterId":        inv.InviterID,
		"inviterEmail":     inviterEmail,
		"teamId":           inv.TeamID,
		"status":           inv.Status,
		"expiresAt":        inv.ExpiresAt,
		"createdAt":        inv.CreatedAt,
	}
}

func rejectInvitationHandler(opts OrganizationOptions) func(*auth.Context) {
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
		if err := c.ParseJSON(&body); err != nil || body.InvitationID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		inv, ok := findPendingRecipientInvitation(c, ext, body.InvitationID, user.Email)
		if !ok {
			return
		}
		if !requireVerifiedInvitationEmail(c, opts, user) {
			return
		}
		org, err := ext.FindOrganizationByID(c.R.Context(), inv.OrganizationID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.BeforeRejectInvitation != nil {
			if err := opts.OrganizationHooks.BeforeRejectInvitation(c.R.Context(), OrganizationInvitationUserHookData{
				Invitation:   *inv,
				User:         *user,
				Organization: *org,
			}); err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
		}
		if err := ext.UpdateInvitationStatus(c.R.Context(), inv.ID, constants.InvitationRejected); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvitationNotFound))
			return
		}
		inv.Status = constants.InvitationRejected
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.AfterRejectInvitation != nil {
			if err := opts.OrganizationHooks.AfterRejectInvitation(c.R.Context(), OrganizationInvitationUserHookData{
				Invitation:   *inv,
				User:         *user,
				Organization: *org,
			}); err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
		}
		c.WriteJSON(http.StatusOK, map[string]any{"invitation": inv, "member": nil})
	}
}

func cancelInvitationHandler(opts OrganizationOptions) func(*auth.Context) {
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
		if err := c.ParseJSON(&body); err != nil || body.InvitationID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		inv, err := ext.FindInvitationByID(c.R.Context(), body.InvitationID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvitationNotFound))
			return
		}
		member, err := ext.FindMemberByOrgAndUser(c.R.Context(), inv.OrganizationID, user.ID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		if !organizationMemberHasPermissions(c.R.Context(), ext, opts, inv.OrganizationID, member.Role, map[string][]string{"invitation": []string{"cancel"}}) {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		org, err := ext.FindOrganizationByID(c.R.Context(), inv.OrganizationID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.BeforeCancelInvitation != nil {
			if err := opts.OrganizationHooks.BeforeCancelInvitation(c.R.Context(), OrganizationInvitationCancelHookData{
				Invitation:   *inv,
				CancelledBy:  *user,
				Organization: *org,
			}); err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
		}
		if err := ext.UpdateInvitationStatus(c.R.Context(), inv.ID, constants.InvitationCanceled); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvitationNotFound))
			return
		}
		inv.Status = constants.InvitationCanceled
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.AfterCancelInvitation != nil {
			if err := opts.OrganizationHooks.AfterCancelInvitation(c.R.Context(), OrganizationInvitationCancelHookData{
				Invitation:   *inv,
				CancelledBy:  *user,
				Organization: *org,
			}); err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
		}
		c.WriteJSON(http.StatusOK, inv)
	}
}

func getInvitationHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		_, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		id := c.R.URL.Query().Get("id")
		inv, ok := findPendingRecipientInvitation(c, ext, id, user.Email)
		if !ok {
			return
		}
		if !requireVerifiedInvitationEmail(c, opts, user) {
			return
		}
		org, err := ext.FindOrganizationByID(c.R.Context(), inv.OrganizationID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		out := invitationResponse(c, inv, org)
		c.WriteJSON(http.StatusOK, out)
	}
}

func listOrgInvitationsHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		orgID := organizationIDFromRequest(sess, c.R.URL.Query().Get("organizationId"))
		if orgID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
			return
		}
		if _, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID); err != nil {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		invitations, err := ext.ListInvitationsByOrg(c.R.Context(), orgID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		c.WriteJSON(http.StatusOK, invitations)
	}
}

func listUserInvitationsHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		_, user, ok := c.RequireSession()
		if !ok {
			return
		}
		if !requireVerifiedEmailForInvitationList(c, user) {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		invitations, err := ext.ListInvitationsByEmail(c.R.Context(), user.Email)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		pending := make([]types.Invitation, 0, len(invitations))
		now := time.Now()
		for _, invitation := range invitations {
			if invitation.Status == constants.InvitationPending && now.Before(invitation.ExpiresAt) {
				pending = append(pending, invitation)
			}
		}
		c.WriteJSON(http.StatusOK, pending)
	}
}

func addMemberHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			UserID         string          `json:"userId"`
			Role           json.RawMessage `json:"role"`
			OrganizationID string          `json:"organizationId"`
			TeamID         string          `json:"teamId"`
		}
		if err := c.ParseJSON(&body); err != nil || body.UserID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		role, ok := parseMemberRole(body.Role)
		if !ok {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		orgID := body.OrganizationID
		var sess *types.Session
		var currentUser *types.User
		if session, sessionUser, err := c.GetSession(); err == nil {
			sess = session
			currentUser = sessionUser
		}
		if orgID == "" {
			if sess != nil {
				orgID = organizationIDFromRequest(sess, "")
			}
		}
		if orgID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
			return
		}
		user, err := c.Auth.Store().FindUserByID(c.R.Context(), body.UserID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if _, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID); err == nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		org, err := ext.FindOrganizationByID(c.R.Context(), orgID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		limitReached, err := organizationMembershipLimitReached(c.R.Context(), ext, opts, user, org)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if limitReached {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		if body.TeamID != "" && !organizationTeamsEnabled(opts) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if body.TeamID != "" {
			team, err := ext.FindTeamByID(c.R.Context(), body.TeamID)
			if err != nil || team.OrganizationID != orgID {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			teamLimitReached, err := teamMemberLimitReached(c.R.Context(), ext, opts, body.TeamID, user.ID, orgID, sess, currentUser)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
			if teamLimitReached {
				c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
				return
			}
		}
		now := time.Now()
		memberID, err := id.Generate(32)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		memberData, err := runBeforeAddMemberHook(c.R.Context(), opts, OrganizationMemberCreateData{
			UserID:         user.ID,
			OrganizationID: orgID,
			Role:           role,
		}, user, org)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		member := &types.Member{
			ID:             memberID,
			OrganizationID: memberData.OrganizationID,
			UserID:         memberData.UserID,
			Role:           memberData.Role,
			CreatedAt:      now,
		}
		if body.TeamID != "" {
			teamMemberID, err := id.Generate(32)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
			if err := ext.CreateTeamMember(c.R.Context(), &types.TeamMember{
				ID: teamMemberID, TeamID: body.TeamID, UserID: memberData.UserID, CreatedAt: now,
			}); err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
		}
		if err := ext.CreateMember(c.R.Context(), member); err != nil {
			if body.TeamID != "" {
				_ = ext.DeleteTeamMemberByTeamAndUser(c.R.Context(), body.TeamID, user.ID)
			}
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if err := runAfterAddMemberHook(c.R.Context(), opts, member, user, org); err != nil {
			_ = ext.DeleteMember(c.R.Context(), member.ID)
			if body.TeamID != "" {
				_ = ext.DeleteTeamMemberByTeamAndUser(c.R.Context(), body.TeamID, member.UserID)
			}
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		c.WriteJSON(http.StatusOK, member)
	}
}

func removeMemberHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			MemberID        string `json:"memberId"`
			MemberIDOrEmail string `json:"memberIdOrEmail"`
			OrganizationID  string `json:"organizationId"`
		}
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		orgID := organizationIDFromRequest(sess, body.OrganizationID)
		if orgID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
			return
		}
		updater, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		creatorRole := organizationCreatorRole(opts)
		updaterIsCreator := memberHasRole(updater.Role, creatorRole)
		if !organizationMemberHasPermissions(c.R.Context(), ext, opts, orgID, updater.Role, map[string][]string{"member": []string{"delete"}}) {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		targetKey := body.MemberIDOrEmail
		if targetKey == "" {
			targetKey = body.MemberID
		}
		target, ok := findRemovableMember(c, ext, orgID, targetKey)
		if !ok {
			return
		}
		targetIsCreator := memberHasRole(target.Role, creatorRole)
		if targetIsCreator && !updaterIsCreator {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if targetIsCreator {
			members, err := ext.ListMembersByOrg(c.R.Context(), orgID)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
				return
			}
			if memberRoleCount(members, creatorRole) <= 1 {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
		}
		targetUser, org, ok := runMemberHookData(c.R.Context(), c, ext, target)
		if !ok {
			return
		}
		hookData := OrganizationMemberHookData{
			Member:       *target,
			User:         *targetUser,
			Organization: *org,
		}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.BeforeRemoveMember != nil {
			if err := opts.OrganizationHooks.BeforeRemoveMember(c.R.Context(), hookData); err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
		}
		if err := ext.DeleteMember(c.R.Context(), target.ID); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		if target.UserID == user.ID {
			_, _ = c.Auth.SetSessionAdditional(c.R.Context(), sess.Token, map[string]any{
				constants.SessionActiveOrganizationID: nil,
			})
		}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.AfterRemoveMember != nil {
			if err := opts.OrganizationHooks.AfterRemoveMember(c.R.Context(), hookData); err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
		}
		c.WriteJSON(http.StatusOK, map[string]any{"member": target})
	}
}

func organizationIDFromRequest(sess *types.Session, organizationID string) string {
	if organizationID != "" {
		return organizationID
	}
	if v, exists := auth.SessionAdditional(sess, constants.SessionActiveOrganizationID); exists {
		orgID, _ := v.(string)
		return orgID
	}
	return ""
}

func findRemovableMember(c *auth.Context, ext store.ExtStore, orgID string, value string) (*types.Member, bool) {
	if value == "" {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
		return nil, false
	}
	if strings.Contains(value, "@") {
		user, err := c.Auth.Store().FindUserByEmail(c.R.Context(), auth.NormalizeEmail(value))
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return nil, false
		}
		member, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return nil, false
		}
		return member, true
	}
	member, err := ext.FindMemberByID(c.R.Context(), value)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
		return nil, false
	}
	if member.OrganizationID != orgID {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
		return nil, false
	}
	return member, true
}

func updateMemberRoleHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			MemberID       string          `json:"memberId"`
			OrganizationID string          `json:"organizationId"`
			Role           json.RawMessage `json:"role"`
		}
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		role, ok := parseMemberRole(body.Role)
		if !ok || body.MemberID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		orgID := organizationIDFromRequest(sess, body.OrganizationID)
		if orgID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
			return
		}
		updater, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		target, err := ext.FindMemberByID(c.R.Context(), body.MemberID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		if target.OrganizationID != orgID {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		roleExists, err := organizationRoleExists(c.R.Context(), ext, opts, orgID, role)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if !roleExists {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		creatorRole := organizationCreatorRole(opts)
		updaterIsCreator := memberHasRole(updater.Role, creatorRole)
		if !updaterIsCreator && !organizationMemberHasPermissions(c.R.Context(), ext, opts, orgID, updater.Role, map[string][]string{"member": []string{"update"}}) {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		targetIsCreator := memberHasRole(target.Role, creatorRole)
		settingCreator := memberHasRole(role, creatorRole)
		if (targetIsCreator || settingCreator) && !updaterIsCreator {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		if updater.ID == target.ID && targetIsCreator && !settingCreator {
			members, err := ext.ListMembersByOrg(c.R.Context(), orgID)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
				return
			}
			if memberRoleCount(members, creatorRole) <= 1 {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
		}
		targetUser, org, ok := runMemberHookData(c.R.Context(), c, ext, target)
		if !ok {
			return
		}
		previousRole := target.Role
		nextRole := role
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.BeforeUpdateMemberRole != nil {
			updated, err := opts.OrganizationHooks.BeforeUpdateMemberRole(c.R.Context(), OrganizationMemberRoleUpdateHookData{
				Member:       *target,
				NewRole:      nextRole,
				User:         *targetUser,
				Organization: *org,
			})
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			if updated != nil && updated.Role != "" {
				nextRole = updated.Role
			}
		}
		member, err := ext.UpdateMemberRole(c.R.Context(), body.MemberID, nextRole)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.AfterUpdateMemberRole != nil {
			if err := opts.OrganizationHooks.AfterUpdateMemberRole(c.R.Context(), OrganizationMemberRoleUpdatedHookData{
				Member:       *member,
				PreviousRole: previousRole,
				User:         *targetUser,
				Organization: *org,
			}); err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
		}
		c.WriteJSON(http.StatusOK, member)
	}
}

func parseMemberRole(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err == nil {
		return normalizeMemberRoles([]string{value})
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err == nil {
		return normalizeMemberRoles(values)
	}
	return "", false
}

func normalizeMemberRoles(values []string) (string, bool) {
	roles := make([]string, 0, len(values))
	for _, value := range values {
		for _, role := range strings.Split(value, ",") {
			role = strings.TrimSpace(role)
			if role != "" {
				roles = append(roles, role)
			}
		}
	}
	if len(roles) == 0 {
		return "", false
	}
	return strings.Join(roles, ","), true
}

func memberHasRole(value string, expected string) bool {
	for _, role := range strings.Split(value, ",") {
		if strings.TrimSpace(role) == expected {
			return true
		}
	}
	return false
}

func memberRoleCount(members []types.Member, role string) int {
	count := 0
	for _, member := range members {
		if memberHasRole(member.Role, role) {
			count++
		}
	}
	return count
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
		orgID := organizationIDFromRequest(sess, "")
		if orgID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
			return
		}
		member, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		c.WriteJSON(http.StatusOK, member)
	}
}

func leaveOrgHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
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
		if err := c.ParseJSON(&body); err != nil || body.OrganizationID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		member, err := ext.FindMemberByOrgAndUser(c.R.Context(), body.OrganizationID, user.ID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		creatorRole := organizationCreatorRole(opts)
		if memberHasRole(member.Role, creatorRole) {
			members, err := ext.ListMembersByOrg(c.R.Context(), body.OrganizationID)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
				return
			}
			if memberRoleCount(members, creatorRole) <= 1 {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
		}
		if err := ext.DeleteMember(c.R.Context(), member.ID); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		if activeOrgID, exists := auth.SessionAdditional(sess, constants.SessionActiveOrganizationID); exists && activeOrgID == body.OrganizationID {
			_, _ = c.Auth.SetSessionAdditional(c.R.Context(), sess.Token, map[string]any{
				constants.SessionActiveOrganizationID: nil,
			})
		}
		c.WriteJSON(http.StatusOK, member)
	}
}

func listMembersHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		query := c.R.URL.Query()
		orgID := organizationIDFromRequest(sess, query.Get("organizationId"))
		if slug := query.Get("organizationSlug"); slug != "" {
			org, err := ext.FindOrganizationBySlug(c.R.Context(), slug)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
				return
			}
			orgID = org.ID
		}
		if orgID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
			return
		}
		if _, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID); err != nil {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		members, err := ext.ListMembersByOrg(c.R.Context(), orgID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		members, err = filterMembers(members, query.Get("filterField"), query["filterValue"], query.Get("filterOperator"))
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if err := sortMembers(members, query.Get("sortBy"), query.Get("sortDirection")); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		total := len(members)
		paged, err := paginateMembers(members, query.Get("offset"), query.Get("limit"))
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]any{"members": paged, "total": total})
	}
}

func sortMembers(members []types.Member, sortBy string, direction string) error {
	if direction != "" && direction != "asc" && direction != "desc" {
		return apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest)
	}
	if sortBy == "" {
		return nil
	}
	less, ok := memberLessFunc(members, sortBy, direction == "desc")
	if !ok {
		return apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest)
	}
	sort.SliceStable(members, less)
	return nil
}

func memberLessFunc(members []types.Member, sortBy string, desc bool) (func(int, int) bool, bool) {
	less := func(i int, j int) bool {
		return memberFieldLess(members[i], members[j], sortBy)
	}
	if desc {
		less = func(i int, j int) bool {
			return memberFieldLess(members[j], members[i], sortBy)
		}
	}
	if !memberSortFieldSupported(sortBy) {
		return nil, false
	}
	return less, true
}

func memberSortFieldSupported(sortBy string) bool {
	switch sortBy {
	case "id", "organizationId", "userId", "role", "createdAt":
		return true
	default:
		return false
	}
}

func memberFieldLess(left types.Member, right types.Member, sortBy string) bool {
	switch sortBy {
	case "id":
		return left.ID < right.ID
	case "organizationId":
		return left.OrganizationID < right.OrganizationID
	case "userId":
		return left.UserID < right.UserID
	case "role":
		return left.Role < right.Role
	case "createdAt":
		return left.CreatedAt.Before(right.CreatedAt)
	default:
		return false
	}
}

func filterMembers(members []types.Member, field string, values []string, operator string) ([]types.Member, error) {
	if field == "" {
		return members, nil
	}
	if !memberSortFieldSupported(field) {
		return nil, apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest)
	}
	filterValues := normalizeMemberFilterValues(values)
	if len(filterValues) == 0 {
		return nil, apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest)
	}
	if operator == "" {
		operator = "eq"
	}
	out := make([]types.Member, 0, len(members))
	for _, member := range members {
		matches, err := memberMatchesFilter(member, field, filterValues, operator)
		if err != nil {
			return nil, err
		}
		if matches {
			out = append(out, member)
		}
	}
	return out, nil
}

func normalizeMemberFilterValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func memberMatchesFilter(member types.Member, field string, values []string, operator string) (bool, error) {
	if field == "createdAt" {
		return memberTimeMatchesFilter(member.CreatedAt, values, operator)
	}
	value := memberFieldString(member, field)
	return stringMatchesFilter(value, values, operator)
}

func memberFieldString(member types.Member, field string) string {
	switch field {
	case "id":
		return member.ID
	case "organizationId":
		return member.OrganizationID
	case "userId":
		return member.UserID
	case "role":
		return member.Role
	default:
		return ""
	}
}

func stringMatchesFilter(value string, values []string, operator string) (bool, error) {
	target := values[0]
	switch operator {
	case "eq":
		return value == target, nil
	case "ne":
		return value != target, nil
	case "lt":
		return value < target, nil
	case "lte":
		return value <= target, nil
	case "gt":
		return value > target, nil
	case "gte":
		return value >= target, nil
	case "in":
		return stringSetContains(values, value), nil
	case "not_in":
		return !stringSetContains(values, value), nil
	case "contains":
		return strings.Contains(value, target), nil
	case "starts_with":
		return strings.HasPrefix(value, target), nil
	case "ends_with":
		return strings.HasSuffix(value, target), nil
	default:
		return false, apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest)
	}
}

func memberTimeMatchesFilter(value time.Time, values []string, operator string) (bool, error) {
	target, err := time.Parse(time.RFC3339, values[0])
	if err != nil {
		return false, err
	}
	switch operator {
	case "eq":
		return value.Equal(target), nil
	case "ne":
		return !value.Equal(target), nil
	case "lt":
		return value.Before(target), nil
	case "lte":
		return value.Before(target) || value.Equal(target), nil
	case "gt":
		return value.After(target), nil
	case "gte":
		return value.After(target) || value.Equal(target), nil
	case "in", "not_in":
		return memberTimeInValues(value, values, operator == "not_in")
	default:
		return false, apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest)
	}
}

func memberTimeInValues(value time.Time, values []string, invert bool) (bool, error) {
	matched := false
	for _, raw := range values {
		target, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return false, err
		}
		if value.Equal(target) {
			matched = true
			break
		}
	}
	if invert {
		return !matched, nil
	}
	return matched, nil
}

func paginateMembers(members []types.Member, offsetValue string, limitValue string) ([]types.Member, error) {
	offset, hasOffset, err := parseMemberPaginationValue(offsetValue)
	if err != nil {
		return nil, err
	}
	limit, hasLimit, err := parseMemberPaginationValue(limitValue)
	if err != nil {
		return nil, err
	}
	if !hasOffset {
		offset = 0
	}
	if offset > len(members) {
		offset = len(members)
	}
	end := len(members)
	if hasLimit && offset+limit < end {
		end = offset + limit
	}
	return members[offset:end], nil
}

func parseMemberPaginationValue(value string) (int, bool, error) {
	if value == "" {
		return 0, false, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, false, err
	}
	if parsed < 0 {
		return 0, false, apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest)
	}
	return parsed, true, nil
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
		query := c.R.URL.Query()
		orgID := organizationIDFromRequest(sess, query.Get("organizationId"))
		if slug := query.Get("organizationSlug"); slug != "" {
			org, err := ext.FindOrganizationBySlug(c.R.Context(), slug)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
				return
			}
			orgID = org.ID
		}
		if orgID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
			return
		}
		currentMember, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		userID := query.Get("userId")
		if userID == "" {
			c.WriteJSON(http.StatusOK, map[string]string{"role": currentMember.Role})
			return
		}
		member, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, userID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]string{"role": member.Role})
	}
}

func normalizeOrganizationRoleName(role string) string {
	return strings.ToLower(strings.TrimSpace(role))
}

func organizationRoleIsStatic(opts OrganizationOptions, role string) bool {
	_, ok := organizationRolePermissions(opts)[role]
	return ok
}

func resolveDynamicRoleOrganization(ctx context.Context, ext store.ExtStore, opts OrganizationOptions, sess *types.Session, userID string, organizationID string, permissions map[string][]string) (string, bool) {
	orgID := organizationIDFromRequest(sess, organizationID)
	if orgID == "" {
		return "", false
	}
	member, err := ext.FindMemberByOrgAndUser(ctx, orgID, userID)
	if err != nil {
		return "", false
	}
	return orgID, organizationMemberHasPermissions(ctx, ext, opts, orgID, member.Role, permissions)
}

func findOrganizationRoleByRequest(ctx context.Context, ext store.ExtStore, organizationID string, roleID string, roleName string) (*types.OrganizationRole, error) {
	if roleID != "" {
		role, err := ext.FindOrganizationRoleByID(ctx, roleID)
		if err != nil {
			return nil, err
		}
		if role.OrganizationID != organizationID {
			return nil, berrors.ErrNotFound
		}
		return role, nil
	}
	if roleName == "" {
		return nil, berrors.ErrNotFound
	}
	return ext.FindOrganizationRoleByOrgAndRole(ctx, organizationID, normalizeOrganizationRoleName(roleName))
}

func createOrgRoleHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			OrganizationID string              `json:"organizationId"`
			Role           string              `json:"role"`
			Permission     map[string][]string `json:"permission"`
		}
		if err := c.ParseJSON(&body); err != nil || body.Role == "" || len(body.Permission) == 0 {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		orgID, allowed := resolveDynamicRoleOrganization(c.R.Context(), ext, opts, sess, user.ID, body.OrganizationID, map[string][]string{"ac": []string{"create"}})
		if !allowed {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		roleName := normalizeOrganizationRoleName(body.Role)
		if _, exists := organizationRolePermissions(opts)[roleName]; exists {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		maximum, err := organizationMaximumRoles(c.R.Context(), opts, orgID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if maximum > 0 {
			roles, err := ext.ListOrganizationRolesByOrg(c.R.Context(), orgID)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
			if len(roles) >= maximum {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
		}
		roleID, err := id.Generate(32)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		role := &types.OrganizationRole{
			ID:             roleID,
			OrganizationID: orgID,
			Role:           roleName,
			Permission:     body.Permission,
			CreatedAt:      time.Now(),
		}
		if err := ext.CreateOrganizationRole(c.R.Context(), role); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]any{"success": true, "roleData": role, "statements": role.Permission})
	}
}

func updateOrgRoleHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			OrganizationID string `json:"organizationId"`
			RoleID         string `json:"roleId"`
			RoleName       string `json:"roleName"`
			Data           struct {
				RoleName   string              `json:"roleName"`
				Permission map[string][]string `json:"permission"`
			} `json:"data"`
		}
		if err := c.ParseJSON(&body); err != nil || (body.RoleID == "" && body.RoleName == "") {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		orgID, allowed := resolveDynamicRoleOrganization(c.R.Context(), ext, opts, sess, user.ID, body.OrganizationID, map[string][]string{"ac": []string{"update"}})
		if !allowed {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		role, err := findOrganizationRoleByRequest(c.R.Context(), ext, orgID, body.RoleID, body.RoleName)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		nextRoleName := role.Role
		if body.Data.RoleName != "" {
			nextRoleName = normalizeOrganizationRoleName(body.Data.RoleName)
			if organizationRoleIsStatic(opts, nextRoleName) {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
		}
		nextPermission := role.Permission
		if len(body.Data.Permission) > 0 {
			nextPermission = body.Data.Permission
		}
		updated, err := ext.UpdateOrganizationRole(c.R.Context(), role.ID, nextRoleName, nextPermission)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]any{"success": true, "roleData": updated})
	}
}

func deleteOrgRoleHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			OrganizationID string `json:"organizationId"`
			RoleID         string `json:"roleId"`
			RoleName       string `json:"roleName"`
		}
		if err := c.ParseJSON(&body); err != nil || (body.RoleID == "" && body.RoleName == "") {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		orgID, allowed := resolveDynamicRoleOrganization(c.R.Context(), ext, opts, sess, user.ID, body.OrganizationID, map[string][]string{"ac": []string{"delete"}})
		if !allowed {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		if body.RoleName != "" && organizationRoleIsStatic(opts, normalizeOrganizationRoleName(body.RoleName)) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		role, err := findOrganizationRoleByRequest(c.R.Context(), ext, orgID, body.RoleID, body.RoleName)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		members, err := ext.ListMembersByOrg(c.R.Context(), orgID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		for _, member := range members {
			if memberHasRole(member.Role, role.Role) {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
		}
		if err := ext.DeleteOrganizationRole(c.R.Context(), role.ID); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func listOrgRolesHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		orgID, allowed := resolveDynamicRoleOrganization(c.R.Context(), ext, opts, sess, user.ID, c.R.URL.Query().Get("organizationId"), map[string][]string{"ac": []string{"read"}})
		if !allowed {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		roles, err := ext.ListOrganizationRolesByOrg(c.R.Context(), orgID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		c.WriteJSON(http.StatusOK, roles)
	}
}

func getOrgRoleHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		query := c.R.URL.Query()
		orgID, allowed := resolveDynamicRoleOrganization(c.R.Context(), ext, opts, sess, user.ID, query.Get("organizationId"), map[string][]string{"ac": []string{"read"}})
		if !allowed {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		role, err := findOrganizationRoleByRequest(c.R.Context(), ext, orgID, query.Get("roleId"), query.Get("roleName"))
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		c.WriteJSON(http.StatusOK, role)
	}
}

func hasOrgPermissionHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			OrganizationID string              `json:"organizationId"`
			Permission     map[string][]string `json:"permission"`
			Permissions    map[string][]string `json:"permissions"`
		}
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		permissions := body.Permissions
		if len(permissions) == 0 {
			permissions = body.Permission
		}
		if len(permissions) == 0 {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		orgID := organizationIDFromRequest(sess, body.OrganizationID)
		if orgID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
			return
		}
		member, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeUnauthorized))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]any{
			"error":   nil,
			"success": organizationMemberHasPermissions(c.R.Context(), ext, opts, orgID, member.Role, permissions),
		})
	}
}

func organizationMemberHasPermissions(ctx context.Context, ext store.ExtStore, opts OrganizationOptions, organizationID string, roleValue string, permissions map[string][]string) bool {
	for _, role := range strings.Split(roleValue, ",") {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		if roleAllowsPermissions(opts, role, permissions) {
			return true
		}
		customRole, err := ext.FindOrganizationRoleByOrgAndRole(ctx, organizationID, role)
		if err == nil && permissionAllows(customRole.Permission, permissions) {
			return true
		}
	}
	return false
}

func roleAllowsPermissions(opts OrganizationOptions, role string, permissions map[string][]string) bool {
	allowed, ok := organizationRolePermissions(opts)[role]
	if !ok {
		return false
	}
	return permissionAllows(allowed, permissions)
}

func organizationRoleExists(ctx context.Context, ext store.ExtStore, opts OrganizationOptions, organizationID string, roleValue string) (bool, error) {
	for _, role := range strings.Split(roleValue, ",") {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		if _, ok := organizationRolePermissions(opts)[role]; ok {
			continue
		}
		if !organizationDynamicAccessControlEnabled(opts) {
			return false, nil
		}
		if _, err := ext.FindOrganizationRoleByOrgAndRole(ctx, organizationID, role); err != nil {
			if stderrors.Is(err, berrors.ErrNotFound) {
				return false, nil
			}
			return false, err
		}
	}
	return true, nil
}

func permissionAllows(allowed map[string][]string, permissions map[string][]string) bool {
	for resource, actions := range permissions {
		allowedActions, ok := allowed[resource]
		if !ok {
			return false
		}
		for _, action := range actions {
			if !stringSetContains(allowedActions, action) {
				return false
			}
		}
	}
	return true
}

func defaultOrganizationRolePermissions() map[string]map[string][]string {
	return map[string]map[string][]string{
		constants.RoleOwner: {
			"organization": []string{"update", "delete"},
			"member":       []string{"create", "update", "delete"},
			"invitation":   []string{"create", "cancel"},
			"team":         []string{"create", "update", "delete"},
			"ac":           []string{"create", "read", "update", "delete"},
		},
		constants.RoleAdmin: {
			"organization": []string{"update"},
			"invitation":   []string{"create", "cancel"},
			"member":       []string{"create", "update", "delete"},
			"team":         []string{"create", "update", "delete"},
			"ac":           []string{"create", "read", "update", "delete"},
		},
		"member": {
			"ac": []string{"read"},
		},
	}
}

func organizationRolePermissions(opts OrganizationOptions) map[string]map[string][]string {
	permissions := defaultOrganizationRolePermissions()
	for role, rolePermissions := range opts.Roles {
		permissions[role] = rolePermissions
	}
	return permissions
}

func stringSetContains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func createTeamHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			OrganizationID string `json:"organizationId"`
			Name           string `json:"name"`
		}
		if err := c.ParseJSON(&body); err != nil || body.Name == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		orgID := organizationIDFromRequest(sess, body.OrganizationID)
		if orgID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
			return
		}
		org, err := ext.FindOrganizationByID(c.R.Context(), orgID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		member, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		if !organizationMemberHasPermissions(c.R.Context(), ext, opts, orgID, member.Role, map[string][]string{"team": []string{"create"}}) {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		maximumTeams, err := organizationMaximumTeams(c.R.Context(), opts, OrganizationMaximumTeamsData{
			OrganizationID: orgID,
			Session:        sess,
			User:           user,
		})
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if maximumTeams > 0 {
			teams, err := ext.ListTeamsByOrg(c.R.Context(), orgID)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
				return
			}
			if len(teams) >= maximumTeams {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
		}
		now := time.Now()
		teamID, err := id.Generate(32)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		teamData := OrganizationTeamCreateData{Name: body.Name, OrganizationID: orgID}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.BeforeCreateTeam != nil {
			updated, err := opts.OrganizationHooks.BeforeCreateTeam(c.R.Context(), OrganizationTeamCreateHookData{
				Team:         teamData,
				User:         user,
				Organization: *org,
			})
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			if updated != nil {
				teamData = *updated
			}
		}
		team := &types.Team{ID: teamID, Name: teamData.Name, OrganizationID: teamData.OrganizationID, CreatedAt: now, UpdatedAt: now}
		if err := ext.CreateTeam(c.R.Context(), team); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.AfterCreateTeam != nil {
			if err := opts.OrganizationHooks.AfterCreateTeam(c.R.Context(), OrganizationTeamHookData{
				Team:         *team,
				User:         user,
				Organization: *org,
			}); err != nil {
				_ = ext.DeleteTeam(c.R.Context(), team.ID)
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
		}
		c.WriteJSON(http.StatusOK, team)
	}
}

func removeTeamHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			TeamID         string `json:"teamId"`
			OrganizationID string `json:"organizationId"`
		}
		if err := c.ParseJSON(&body); err != nil || body.TeamID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		orgID := organizationIDFromRequest(sess, body.OrganizationID)
		if orgID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
			return
		}
		member, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID)
		if err != nil || !organizationMemberHasPermissions(c.R.Context(), ext, opts, orgID, member.Role, map[string][]string{"team": []string{"delete"}}) {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		if activeTeamID, exists := auth.SessionAdditional(sess, constants.SessionActiveTeamID); exists && activeTeamID == body.TeamID {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		team, err := ext.FindTeamByID(c.R.Context(), body.TeamID)
		if err != nil || team.OrganizationID != orgID {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		org, err := ext.FindOrganizationByID(c.R.Context(), orgID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		teams, err := ext.ListTeamsByOrg(c.R.Context(), orgID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		if len(teams) <= 1 && !organizationAllowRemovingAllTeams(opts) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		hookData := OrganizationTeamHookData{
			Team:         *team,
			User:         user,
			Organization: *org,
		}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.BeforeDeleteTeam != nil {
			if err := opts.OrganizationHooks.BeforeDeleteTeam(c.R.Context(), hookData); err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
		}
		if err := ext.DeleteTeam(c.R.Context(), body.TeamID); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.AfterDeleteTeam != nil {
			if err := opts.OrganizationHooks.AfterDeleteTeam(c.R.Context(), hookData); err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
		}
		c.WriteJSON(http.StatusOK, map[string]string{"message": "Team removed successfully."})
	}
}

func updateTeamHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			TeamID string `json:"teamId"`
			Data   struct {
				Name           string `json:"name"`
				OrganizationID string `json:"organizationId"`
			} `json:"data"`
			Name           string `json:"name"`
			OrganizationID string `json:"organizationId"`
		}
		if err := c.ParseJSON(&body); err != nil || body.TeamID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		orgID := organizationIDFromRequest(sess, body.Data.OrganizationID)
		if orgID == "" {
			orgID = organizationIDFromRequest(sess, body.OrganizationID)
		}
		if orgID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
			return
		}
		member, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID)
		if err != nil || !organizationMemberHasPermissions(c.R.Context(), ext, opts, orgID, member.Role, map[string][]string{"team": []string{"update"}}) {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		team, err := ext.FindTeamByID(c.R.Context(), body.TeamID)
		if err != nil || team.OrganizationID != orgID {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		org, err := ext.FindOrganizationByID(c.R.Context(), orgID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		name := body.Data.Name
		if name == "" {
			name = body.Name
		}
		updateData := OrganizationTeamUpdateData{Name: name}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.BeforeUpdateTeam != nil {
			updated, err := opts.OrganizationHooks.BeforeUpdateTeam(c.R.Context(), OrganizationTeamUpdateHookData{
				Team:         *team,
				Updates:      updateData,
				User:         *user,
				Organization: *org,
			})
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			if updated != nil {
				updateData = *updated
			}
		}
		updated, err := ext.UpdateTeam(c.R.Context(), body.TeamID, updateData.Name)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.AfterUpdateTeam != nil {
			if err := opts.OrganizationHooks.AfterUpdateTeam(c.R.Context(), OrganizationTeamHookData{
				Team:         *updated,
				User:         user,
				Organization: *org,
			}); err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
		}
		c.WriteJSON(http.StatusOK, updated)
	}
}

func listTeamsHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		orgID := organizationIDFromRequest(sess, c.R.URL.Query().Get("organizationId"))
		if orgID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
			return
		}
		if _, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID); err != nil {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		teams, err := ext.ListTeamsByOrg(c.R.Context(), orgID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		c.WriteJSON(http.StatusOK, teams)
	}
}

func setActiveTeamHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body map[string]json.RawMessage
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		rawTeamID, exists := body["teamId"]
		if exists && string(rawTeamID) == "null" {
			_, _ = c.Auth.SetSessionAdditional(c.R.Context(), sess.Token, map[string]any{constants.SessionActiveTeamID: nil})
			c.WriteNull()
			return
		}
		teamID := ""
		if exists {
			if err := json.Unmarshal(rawTeamID, &teamID); err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
		}
		if teamID == "" {
			if activeTeamID, hasActiveTeam := auth.SessionAdditional(sess, constants.SessionActiveTeamID); hasActiveTeam {
				teamID, _ = activeTeamID.(string)
			}
		}
		if teamID == "" {
			c.WriteNull()
			return
		}
		activeOrgID := organizationIDFromRequest(sess, "")
		if activeOrgID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
			return
		}
		team, err := ext.FindTeamByID(c.R.Context(), teamID)
		if err != nil || team.OrganizationID != activeOrgID {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if _, err := ext.FindTeamMember(c.R.Context(), teamID, user.ID); err != nil {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		if _, err := c.Auth.SetSessionAdditional(c.R.Context(), sess.Token, map[string]any{constants.SessionActiveTeamID: team.ID}); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		c.WriteJSON(http.StatusOK, team)
	}
}

func listUserTeamsHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		_, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		teams, err := ext.ListTeamsByUser(c.R.Context(), user.ID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		out := make([]types.Team, 0, len(teams))
		for _, team := range teams {
			if _, err := ext.FindMemberByOrgAndUser(c.R.Context(), team.OrganizationID, user.ID); err == nil {
				out = append(out, team)
			}
		}
		c.WriteJSON(http.StatusOK, out)
	}
}

func listTeamMembersHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		teamID := c.R.URL.Query().Get("teamId")
		if teamID == "" {
			if activeTeamID, exists := auth.SessionAdditional(sess, constants.SessionActiveTeamID); exists {
				teamID, _ = activeTeamID.(string)
			}
		}
		if teamID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		team, err := ext.FindTeamByID(c.R.Context(), teamID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if _, err := ext.FindMemberByOrgAndUser(c.R.Context(), team.OrganizationID, user.ID); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if _, err := ext.FindTeamMember(c.R.Context(), teamID, user.ID); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		members, err := ext.ListTeamMembers(c.R.Context(), teamID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		c.WriteJSON(http.StatusOK, members)
	}
}

func addTeamMemberHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			TeamID         string `json:"teamId"`
			UserID         string `json:"userId"`
			OrganizationID string `json:"organizationId"`
		}
		if err := c.ParseJSON(&body); err != nil || body.TeamID == "" || body.UserID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		orgID := organizationIDFromRequest(sess, body.OrganizationID)
		if orgID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
			return
		}
		currentMember, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID)
		if err != nil || !organizationMemberHasPermissions(c.R.Context(), ext, opts, orgID, currentMember.Role, map[string][]string{"member": []string{"update"}}) {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		if _, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, body.UserID); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		team, err := ext.FindTeamByID(c.R.Context(), body.TeamID)
		if err != nil || team.OrganizationID != orgID {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		org, err := ext.FindOrganizationByID(c.R.Context(), orgID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		targetUser, err := c.Auth.Store().FindUserByID(c.R.Context(), body.UserID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		pendingTeamMember := types.TeamMember{TeamID: body.TeamID, UserID: body.UserID}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.BeforeAddTeamMember != nil {
			if err := opts.OrganizationHooks.BeforeAddTeamMember(c.R.Context(), OrganizationTeamMemberHookData{
				TeamMember:   pendingTeamMember,
				Team:         *team,
				User:         *targetUser,
				Organization: *org,
			}); err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
		}
		if teamMember, err := ext.FindTeamMember(c.R.Context(), body.TeamID, body.UserID); err == nil {
			if opts.OrganizationHooks != nil && opts.OrganizationHooks.AfterAddTeamMember != nil {
				if err := opts.OrganizationHooks.AfterAddTeamMember(c.R.Context(), OrganizationTeamMemberHookData{
					TeamMember:   *teamMember,
					Team:         *team,
					User:         *targetUser,
					Organization: *org,
				}); err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
			}
			c.WriteJSON(http.StatusOK, teamMember)
			return
		}
		teamLimitReached, err := teamMemberLimitReached(c.R.Context(), ext, opts, body.TeamID, body.UserID, orgID, sess, user)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if teamLimitReached {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		now := time.Now()
		tmID, err := id.Generate(32)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		teamMember := &types.TeamMember{ID: tmID, TeamID: body.TeamID, UserID: body.UserID, CreatedAt: now}
		if err := ext.CreateTeamMember(c.R.Context(), teamMember); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.AfterAddTeamMember != nil {
			if err := opts.OrganizationHooks.AfterAddTeamMember(c.R.Context(), OrganizationTeamMemberHookData{
				TeamMember:   *teamMember,
				Team:         *team,
				User:         *targetUser,
				Organization: *org,
			}); err != nil {
				_ = ext.DeleteTeamMemberByTeamAndUser(c.R.Context(), teamMember.TeamID, teamMember.UserID)
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
		}
		c.WriteJSON(http.StatusOK, teamMember)
	}
}

func removeTeamMemberHandler(opts OrganizationOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		ext, ok := requireExt(c)
		if !ok {
			return
		}
		var body struct {
			TeamMemberID   string `json:"teamMemberId"`
			TeamID         string `json:"teamId"`
			UserID         string `json:"userId"`
			OrganizationID string `json:"organizationId"`
		}
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		orgID := organizationIDFromRequest(sess, body.OrganizationID)
		if orgID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOrganization))
			return
		}
		currentMember, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, user.ID)
		if err != nil || !organizationMemberHasPermissions(c.R.Context(), ext, opts, orgID, currentMember.Role, map[string][]string{"member": []string{"delete"}}) {
			c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
			return
		}
		if body.TeamID == "" || body.UserID == "" {
			if body.TeamMemberID == "" {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			members, err := teamMembersForOrganization(c, ext, orgID)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			for _, member := range members {
				if member.ID == body.TeamMemberID {
					body.TeamID = member.TeamID
					body.UserID = member.UserID
					break
				}
			}
		}
		if body.TeamID == "" || body.UserID == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if _, err := ext.FindMemberByOrgAndUser(c.R.Context(), orgID, body.UserID); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		team, err := ext.FindTeamByID(c.R.Context(), body.TeamID)
		if err != nil || team.OrganizationID != orgID {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		teamMember, err := ext.FindTeamMember(c.R.Context(), body.TeamID, body.UserID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		org, err := ext.FindOrganizationByID(c.R.Context(), orgID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOrgNotFound))
			return
		}
		targetUser, err := c.Auth.Store().FindUserByID(c.R.Context(), body.UserID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		hookData := OrganizationTeamMemberHookData{
			TeamMember:   *teamMember,
			Team:         *team,
			User:         *targetUser,
			Organization: *org,
		}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.BeforeRemoveTeamMember != nil {
			if err := opts.OrganizationHooks.BeforeRemoveTeamMember(c.R.Context(), hookData); err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
		}
		if err := ext.DeleteTeamMemberByTeamAndUser(c.R.Context(), body.TeamID, body.UserID); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		if opts.OrganizationHooks != nil && opts.OrganizationHooks.AfterRemoveTeamMember != nil {
			if err := opts.OrganizationHooks.AfterRemoveTeamMember(c.R.Context(), hookData); err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
		}
		c.WriteJSON(http.StatusOK, map[string]string{"message": "Team member removed successfully."})
	}
}

func teamMembersForOrganization(c *auth.Context, ext store.ExtStore, organizationID string) ([]types.TeamMember, error) {
	teams, err := ext.ListTeamsByOrg(c.R.Context(), organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]types.TeamMember, 0)
	for _, team := range teams {
		members, err := ext.ListTeamMembers(c.R.Context(), team.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, members...)
	}
	return out, nil
}
