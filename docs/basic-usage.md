# Basic usage

A complete auth server is an `auth.New(...)` call and a mounted handler.

```go
package main

import (
	"log"
	"net/http"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/store/memory"
)

func main() {
	a, err := auth.New(auth.Config{
		Secret:         "your-secret-at-least-32-chars-long",
		BaseURL:        "http://localhost:8080",
		TrustedOrigins: []string{"http://localhost:3000"}, // your frontend origin(s)
		Store:          memory.New(),
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	// Every Better Auth endpoint is served under the base path.
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", a.Handler()))

	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

`auth.New` returns an error if `Secret` or `Store` is missing.

## Required vs. common options

| Option | Required | Notes |
|--------|----------|-------|
| `Secret` | ✅ | Signs cookies and tokens |
| `Store` | ✅ | Persistence (`memory`, `sql`, or custom) |
| `BaseURL` | recommended | Used for callback URLs and added to trusted origins |
| `TrustedOrigins` | recommended | Drives CORS **and** CSRF; supports wildcards |
| `BasePath` | optional | Defaults to `/api/auth` |

The full surface is in the [configuration reference](reference/configuration.md).

## Try it

```bash
go run .

# health check
curl http://localhost:8080/api/auth/ok           # {"ok":true}

# sign up (returns a session cookie)
curl -X POST http://localhost:8080/api/auth/sign-up/email \
  -H 'Content-Type: application/json' \
  -d '{"name":"Jane","email":"jane@example.com","password":"password123"}'
```

## Wire up a client

```ts
// auth-client.ts
import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient({
  baseURL: "http://localhost:8080", // your Go server
});

await authClient.signUp.email({ name: "Jane", email: "jane@example.com", password: "password123" });
const { data: session } = await authClient.getSession();
```

See [Integrations → Clients](integrations/clients.md). Next steps:

- [Email & password options](authentication/email-password.md)
- [Social providers](authentication/social-providers.md)
- [Production checklist](guides/production.md)
