# Organization plugin

Multi-tenant organizations with members, roles, invitations, and teams.

## Enable

```go
Plugins: []auth.Plugin{
    plugins.Organization(plugins.OrganizationOptions{
        AllowUserToCreateOrganization: true,
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

Generates organization-related tables. Include in migrations:

```bash
betterauth generate --plugins organization --dialect postgres
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
| POST | `/organization/remove-member` | Remove member |
| POST | `/organization/update-member-role` | Change role |
| POST | `/organization/create-team` | Create team |
| POST | `/organization/set-active-team` | Set active team |

Full route list: enable **open-api** plugin or call `GET /client-schema`.

## Roles

Default roles: `owner`, `admin`, `member`. Active organization and team IDs are
stored in session `additional` fields (`activeOrganizationId`,
`activeTeamId`).

## Example

```ts
await authClient.organization.create({
  name: "Acme Inc",
  slug: "acme",
});

await authClient.organization.setActive({ organizationId: org.id });
```

Back to: [Plugin overview](overview.md)
