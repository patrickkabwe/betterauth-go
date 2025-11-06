# Client schema & additional fields

The Go server exposes `GET /client-schema` so Better Auth clients can infer
types, discover enabled plugins, and pair client plugins with server plugins.

## Additional user fields

Define custom fields on the user object:

```go
User: auth.UserConfig{
    AdditionalFields: map[string]auth.AdditionalFieldDef{
        "company": {
            Type:     "string",
            Required: false,
        },
        "planTier": {
            Type:         "string",
            Required:     true,
            DefaultValue: "free",
        },
        "metadata": {
            Type: "json",
        },
    },
},
```

Supported types: `string`, `number`, `boolean`, `json`.

Values are stored in the portable JSON `additional` column (not dedicated DB
columns). Set `Input: false` on a field to prevent client writes.

Fields appear in sign-up/update payloads and in session user objects.

## Client schema endpoint

```bash
curl http://localhost:8080/api/auth/client-schema
```

Returns JSON describing:

- `features` — email/password, social providers, bearer
- `user` — additional field definitions
- `plugins` — enabled plugins with client pairing info
- `routes` — all HTTP endpoints

## TypeScript inference

Generate types from the running server:

```bash
node scripts/generate-client-types.mjs http://localhost:8080
```

Use with the client:

```ts
import { inferAdditionalFields } from "better-auth/client/plugins";
import type { Auth } from "./auth-types";

createAuthClient({
  plugins: [inferAdditionalFields<Auth>()],
});
```

See [`examples/react/README.md`](../../examples/react/README.md).

## Go client

The Go `client` package can fetch the schema programmatically:

```go
import "github.com/patrickkabwe/betterauth-go/client"

c := client.New("http://localhost:8080")
schema, err := c.FetchSchema(ctx)
```

Next: [Server API →](server-api.md)
