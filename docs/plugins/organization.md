# Organization plugin

Multi-tenant organizations with members, roles, invitations, and teams.

## Enable

```go
allowOrganizationCreation := true
createDefaultTeam := true
requireInvitationVerification := true

Plugins: []auth.Plugin{
    plugins.Organization(plugins.OrganizationOptions{
        AllowUserToCreateOrganization: &allowOrganizationCreation,
        AllowUserToCreateOrganizationFunc: func(ctx context.Context, user types.User) (bool, error) {
            return true, nil
        },
        CreatorRole: "owner",
        OrganizationLimit: 10,
        OrganizationLimitReached: func(ctx context.Context, user types.User) (bool, error) {
            return false, nil
        },
        MembershipLimit: 100,
        MembershipLimitFunc: func(ctx context.Context, user types.User, org types.Organization) (int, error) {
            return 100, nil
        },
        InvitationExpiresIn: 48 * time.Hour,
        InvitationLimit: 100,
        InvitationLimitFunc: func(ctx context.Context, data plugins.OrganizationInvitationLimitData) (int, error) {
            return 100, nil
        },
        CancelPendingInvitationsOnReInvite: false,
        RequireEmailVerificationOnInvitation: &requireInvitationVerification,
        DisableOrganizationDeletion: false,
        Roles: map[string]map[string][]string{
            "reviewer": {
                "organization": []string{"update"},
            },
        },
        DynamicAccessControl: &plugins.OrganizationDynamicAccessControlOptions{
            Enabled: true,
            MaximumRolesPerOrganization: 20,
            MaximumRolesPerOrganizationFunc: func(ctx context.Context, organizationID string) (int, error) {
                return 20, nil
            },
        },
        Teams: &plugins.OrganizationTeamsOptions{
            Enabled: true,
            MaximumTeams: 20,
            MaximumTeamsFunc: func(ctx context.Context, data plugins.OrganizationMaximumTeamsData) (int, error) {
                return 20, nil
            },
            MaximumMembersPerTeam: 50,
            MaximumMembersPerTeamFunc: func(ctx context.Context, data plugins.OrganizationMaximumMembersPerTeamData) (int, error) {
                return 50, nil
            },
            AllowRemovingAllTeams: false,
            DefaultTeam: &plugins.OrganizationDefaultTeamOptions{
                Enabled: &createDefaultTeam,
                CustomCreateDefaultTeam: func(ctx context.Context, org types.Organization, user types.User) (*types.Team, error) {
                    return nil, nil
                },
            },
        },
    }),
},
```

Requires `store.ExtStore` (SQL or memory adapter).

## Client

```ts
import { organizationClient } from "better-auth/client/plugins";

createAuthClient({
  plugins: [organizationClient()],
});
```

## Schema

Generates organization-related tables. Include team schema only when teams are enabled:

```bash
betterauth-go generate --plugins organization,organization-teams,organization-roles --dialect postgres
```

## Key endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/organization/create` | Create org (user becomes owner) |
| POST | `/organization/check-slug` | Slug availability |
| GET | `/organization/list` | User's organizations |
| POST | `/organization/set-active` | Set active org on session |
| GET | `/organization/get-full-organization` | Org + members |
| POST | `/organization/invite-member` | Send invitation |
| POST | `/organization/accept-invitation` | Accept invite |
| POST | `/organization/add-member` | Add member (server-only) |
| POST | `/organization/remove-member` | Remove member |
| POST | `/organization/update-member-role` | Change role |
| POST | `/organization/create-team` | Create team (teams enabled) |
| POST | `/organization/set-active-team` | Set active team (teams enabled) |

Full route list: enable **open-api** plugin or call `GET /client-schema`.

## Roles

Default roles: `owner`, `admin`, `member`. Active organization IDs are stored
in session `additional.activeOrganizationId`; when teams are enabled, active
team IDs are stored in `additional.activeTeamId`. With teams enabled, creating
an organization creates a default team named after the organization unless
`DefaultTeam.Enabled` is explicitly set to `false`. Set
`DefaultTeam.CustomCreateDefaultTeam` to replace the built-in default-team
creation. The callback must persist and return the created team; returning `nil`
uses the built-in creation path.

Invitations expire after `InvitationExpiresIn` (default `48 * time.Hour`) and
the plugin allows up to `InvitationLimit` active pending invitations per
organization (default `100`). Resending a pending invitation refreshes its
expiry. Set `CancelPendingInvitationsOnReInvite` to cancel an existing pending
invitation and create a new one when inviting the same email again.
`SendInvitationEmail` runs after a new invitation is created and after a resend
refreshes an existing pending invitation. Set
`RequireEmailVerificationOnInvitation` to require verified recipient email
before by-ID invitation actions such as accept, reject, and get. Session-based
`/organization/list-user-invitations` requires verified email.

Static limit fields mirror Better Auth JS defaults. Use the callback fields
when limits depend on the current user, organization, member, session, or team.
`OrganizationLimitReached` follows Better Auth JS semantics: it returns whether
the user has already reached the organization limit.

Use `Roles` to configure static custom role permissions. Invitations and member
role updates reject unknown roles unless the role is a default role, a configured
static role, or an existing dynamic access-control role.

Set `DynamicAccessControl.Enabled` to add custom organization-role storage and
role CRUD endpoints. Custom roles use the Better Auth JS `organizationRole`
table and participate in `/organization/has-permission`.

Set `DisableOrganizationDeletion` to make `/organization/delete` unavailable.
`OrganizationHooks` supports Better Auth JS-style callbacks around organization
create, update, and delete operations, plus member add, remove, and role update
operations, invitation create, accept, reject, and cancel operations, and team
create, update, delete, add-member, and remove-member operations.

## Example

```ts
await authClient.organization.create({
  name: "Acme Inc",
  slug: "acme",
});

await authClient.organization.setActive({ organizationId: org.id });
```

Back to: [Plugin overview](overview.md)
