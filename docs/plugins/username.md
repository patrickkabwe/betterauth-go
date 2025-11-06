# Username plugin

Sign in with username in addition to email.

## Enable

```go
Plugins: []auth.Plugin{
    plugins.Username(plugins.UsernameOptions{}),
},
```

Stores `username` and `displayUsername` in user `additional` JSON.

## Client

```ts
import { usernameClient } from "better-auth/client/plugins";

createAuthClient({ plugins: [usernameClient()] });

await authClient.signUp.email({
  name: "Jane",
  email: "jane@example.com",
  password: "password123",
  username: "jane_doe",
});

await authClient.signIn.username({
  username: "jane_doe",
  password: "password123",
});
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/sign-in/username` | Sign in with username + password |
| POST | `/is-username-available` | Check username availability |

Usernames are validated and normalized per Better Auth rules.

Back to: [Plugin overview](overview.md)
