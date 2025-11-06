# Error codes

API errors return `{ "code": "…", "message": "…" }`. Messages are human-readable
defaults; clients should branch on `code`.

## Authentication

| Code | Message (default) |
|------|-------------------|
| `INVALID_EMAIL` | Invalid email |
| `INVALID_PASSWORD` | Invalid password |
| `INVALID_EMAIL_OR_PASSWORD` | Invalid email or password |
| `PASSWORD_TOO_SHORT` | Password is too short |
| `PASSWORD_TOO_LONG` | Password is too long |
| `EMAIL_NOT_VERIFIED` | Email not verified |
| `EMAIL_PASSWORD_SIGN_UP_DISABLED` | Email and password sign up is not enabled |
| `INVALID_USERNAME` | Invalid username |
| `INVALID_CREDENTIAL` | Invalid credentials |

## Session

| Code | Message (default) |
|------|-------------------|
| `UNAUTHORIZED` | Unauthorized |
| `SESSION_EXPIRED` | Session expired |
| `SESSION_NOT_FRESH` | Session is not fresh |
| `FAILED_TO_CREATE_SESSION` | Failed to create session |

## Tokens & verification

| Code | Message (default) |
|------|-------------------|
| `INVALID_TOKEN` | Invalid token |
| `TOKEN_EXPIRED` | Session expired. Re-authenticate… |
| `RESET_PASSWORD_DISABLED` | Reset password isn't enabled |
| `VERIFICATION_EMAIL_NOT_ENABLED` | Verification email isn't enabled |

## User management

| Code | Message (default) |
|------|-------------------|
| `USER_NOT_FOUND` | User not found |
| `FAILED_TO_CREATE_USER` | Failed to create user |
| `INVALID_USER` | Invalid user |
| `EMAIL_CAN_NOT_BE_UPDATED` | Email can not be updated |
| `EMAIL_IS_THE_SAME` | Email is the same |
| `CHANGE_EMAIL_DISABLED` | Change email is disabled |
| `PASSWORD_ALREADY_SET` | Password already set |
| `CREDENTIAL_ACCOUNT_NOT_FOUND` | Credential account not found |
| `DELETE_USER_DISABLED` | Not found |

## OAuth & accounts

| Code | Message (default) |
|------|-------------------|
| `PROVIDER_NOT_FOUND` | Provider not found |
| `PROVIDER_NOT_CONFIGURED` | Provider not configured |
| `PROVIDER_NOT_SUPPORTED` | Provider is not supported |
| `OAUTH_ERROR` | Invalid OAuth callback |
| `OAUTH_NOT_IMPLEMENTED` | OAuth not implemented |
| `LINKING_NOT_ALLOWED` | Linking not allowed |
| `LINKING_DIFFERENT_EMAILS_NOT_ALLOWED` | Linking different emails not allowed |
| `ACCOUNT_NOT_FOUND` | Account not found |
| `FAILED_TO_UNLINK_LAST_ACCOUNT` | Failed to unlink last account |

## Plugins

| Code | Message (default) |
|------|-------------------|
| `FEATURE_NOT_ENABLED` | Feature not enabled |
| `MAGIC_LINK_DISABLED` | Magic link is not configured |
| `EMAIL_OTP_DISABLED` | Email OTP not configured |
| `TWO_FACTOR_NOT_ENABLED` | 2FA not enabled |
| `FORBIDDEN` | Admin access required |
| `ORG_NOT_FOUND` | Organization not found |
| `EXT_STORE_REQUIRED` | ExtStore required |

## Request validation

| Code | Message (default) |
|------|-------------------|
| `BODY_MUST_BE_AN_OBJECT` | Body must be an object |
| `MISSING_FIELD` | {field} is required |
| `INVALID_FIELD` | Invalid field |
| `INVALID_REQUEST` | Invalid request |
| `INVALID_ORIGIN` | Request origin is not trusted |
| `METHOD_NOT_ALLOWED` | POST get-session requires deferSessionRefresh |

## Infrastructure

| Code | Message (default) |
|------|-------------------|
| `INTERNAL_SERVER_ERROR` | Internal server error |

Full list: [`constants/constants.go`](../../constants/constants.go).

Back to: [Errors concept](../concepts/errors.md)
