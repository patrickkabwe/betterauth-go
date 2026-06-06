# Better Auth React Client Example

React + Vite playground using the official [`better-auth/react`](https://better-auth.com/docs/concepts/client) client against the Go server in this repo.

## Prerequisites

- Node.js 18+
- Go server running (see below)

## Run

**Terminal 1 — Go auth server**

```bash
cd ../..   # repo root
go run ./examples/basic
```

The server uses SQLite (`better-auth-example.db` in the working directory) so organization and two-factor plugins work. Email links, OTPs, and magic links are **logged to this terminal**.

**Terminal 2 — React client**

```bash
cd examples/react
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173).

## Configuration

Copy `.env.example` to `.env` if you need a different auth server URL:

```bash
cp .env.example .env
```

```env
VITE_AUTH_URL=http://localhost:8080
```

### OAuth (optional)

On the Go server, set:

```bash
export GOOGLE_CLIENT_ID=...
export GOOGLE_CLIENT_SECRET=...
export GITHUB_CLIENT_ID=...
export GITHUB_CLIENT_SECRET=...
```

Restart the server; Google/GitHub buttons appear automatically (read from `GET /api/auth/client-schema`).

## What the playground covers

### Core auth

- Email sign-up / sign-in / sign-out
- Session display + bearer token (`set-auth-token` header)
- Update profile, change password, change email, set password (OAuth users)
- Verify password, send verification email, request password reset
- Delete account (password or email confirmation link in server logs)
- List / revoke sessions

### OAuth

- Sign in with Google / GitHub
- List, link, and unlink social accounts

### Plugins (server + matching client plugins)

| Plugin | UI section |
|--------|------------|
| `username` | Username sign-in, availability check, profile username |
| `organization` | Create org, list, set active, invite member |
| `two-factor` | Enable TOTP, verify code, disable |
| `anonymous` | Guest sign-in |
| `magic-link` | Send link (URL in server terminal) |
| `email-otp` | Send OTP + sign in (OTP in server terminal) |
| `last-login-method` | Shown on session panel when cookie is set |
| `bearer` | Token preview on session card |

## Type inference from server

With the Go server running:

```bash
node ../../scripts/generate-client-types.mjs
```

This fetches `GET /api/auth/client-schema` and writes `auth-types.generated.ts`.

## Auth client setup

```ts
// src/lib/auth-client.ts
import { createAuthClient } from "better-auth/react";
import {
  anonymousClient,
  emailOTPClient,
  inferAdditionalFields,
  lastLoginMethodClient,
  magicLinkClient,
  organizationClient,
  twoFactorClient,
  usernameClient,
} from "better-auth/client/plugins";
```
