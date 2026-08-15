package constants

// Provider IDs.
const (
	ProviderCredential = "credential"
	ProviderGoogle     = "google"
	ProviderGitHub     = "github"
	ProviderDiscord    = "discord"
	ProviderDropbox    = "dropbox"
	ProviderFigma      = "figma"
	ProviderGitLab     = "gitlab"
	ProviderNotion     = "notion"
	ProviderSlack      = "slack"
	ProviderSpotify    = "spotify"
	ProviderVercel     = "vercel"
)

// User additional field keys.
const (
	FieldRole             = "role"
	FieldBanned           = "banned"
	FieldBanReason        = "banReason"
	FieldBanExpires       = "banExpires"
	FieldIsAnonymous      = "isAnonymous"
	FieldUsername         = "username"
	FieldDisplayUsername  = "displayUsername"
	FieldPhoneNumber      = "phoneNumber"
	FieldPhoneVerified    = "phoneNumberVerified"
	FieldTwoFactorEnabled = "twoFactorEnabled"
	FieldLastLoginMethod  = "lastLoginMethod"
)

// Session additional field keys.
const (
	SessionImpersonatedBy       = "impersonatedBy"
	SessionActiveOrganizationID = "activeOrganizationId"
	SessionActiveTeamID         = "activeTeamId"
)

// Roles.
const (
	RoleUser  = "user"
	RoleAdmin = "admin"
	RoleOwner = "owner"
)

// Invitation statuses.
const (
	InvitationPending  = "pending"
	InvitationAccepted = "accepted"
	InvitationRejected = "rejected"
	InvitationCanceled = "canceled"
)

// Device authorization statuses.
const (
	DeviceStatusPending  = "pending"
	DeviceStatusApproved = "approved"
	DeviceStatusDenied   = "denied"
)

// Verification identifier prefixes.
const (
	VerificationResetPassword = "reset-password:"
	VerificationOAuthState    = "oauth-state:"
	VerificationOAuth2State   = "oauth2-state:"
	VerificationEmailOTP      = "email-otp:"
	VerificationPhoneOTP      = "phone-otp:"
	VerificationOneTimeToken  = "one-time-token:"
	VerificationSIWENonce     = "siwe-nonce:"
	VerificationOIDCCode      = "oidc-code:"
	VerificationOIDCAccess    = "oidc-access:"
	VerificationMCPCode       = "mcp-code:"
	VerificationMCPAccess     = "mcp-access:"
)

// Email OTP types.
const (
	EmailOTPTypeVerification   = "email-verification"
	EmailOTPTypeForgetPassword = "forget-password"
	EmailOTPTypeEmailChange    = "change-email"
)

// Domain suffixes for synthetic emails.
const (
	DomainAnonymous = "anonymous.local"
	DomainPhone     = "phone.local"
	DomainWallet    = "wallet.local"
)

// HTTP headers.
const (
	HeaderContentType         = "Content-Type"
	HeaderAuthorization       = "Authorization"
	HeaderSetAuthToken        = "set-auth-token"
	HeaderAccessControlExpose = "Access-Control-Expose-Headers"
	HeaderCaptchaResponse     = "x-captcha-response"
	HeaderLastLoginMethod     = "X-Last-Login-Method"
	HeaderAccept              = "Accept"
	MIMEJSON                  = "application/json"
)

// Cookie names.
const (
	CookieLastLoginMethod = "better-auth.last_login_method"
)

// JWT / OAuth.
const (
	JWTAlgHS256        = "HS256"
	JWTTypeJWT         = "JWT"
	JWTKtyOct          = "oct"
	OAuthGrantTypeCode = "authorization_code"
	TokenTypeBearer    = "Bearer"
)

// OAuth application types.
const (
	OAuthAppTypeWeb = "web"
	OAuthAppTypeMCP = "mcp"
)

// Plugin IDs.
const (
	PluginBearer            = "bearer"
	PluginMagicLink         = "magic-link"
	PluginAnonymous         = "anonymous"
	PluginUsername          = "username"
	PluginEmailOTP          = "email-otp"
	PluginOneTimeToken      = "one-time-token"
	PluginJWT               = "jwt"
	PluginMultiSession      = "multi-session"
	PluginCustomSession     = "custom-session"
	PluginLastLoginMethod   = "last-login-method"
	PluginHaveIBeenPwned    = "have-i-been-pwned"
	PluginCaptcha           = "captcha"
	PluginOAuthProxy        = "oauth-proxy"
	PluginGenericOAuth      = "generic-oauth"
	PluginOneTap            = "one-tap"
	PluginOpenAPI           = "open-api"
	PluginDeviceAuth        = "device-authorization"
	PluginPhoneNumber       = "phone-number"
	PluginSIWE              = "siwe"
	PluginTwoFactor         = "two-factor"
	PluginAdmin             = "admin"
	PluginOrganization      = "organization"
	PluginOrganizationTeams = "organization-teams"
	PluginOrganizationRoles = "organization-roles"
	PluginOIDCProvider      = "oidc-provider"
	PluginMCP               = "mcp"
	PluginAPIKey            = "api-key"
)

// API error codes.
const (
	CodeInvalidEmail                = "INVALID_EMAIL"
	CodeInvalidPassword             = "INVALID_PASSWORD"
	CodeInvalidEmailOrPassword      = "INVALID_EMAIL_OR_PASSWORD"
	CodePasswordTooShort            = "PASSWORD_TOO_SHORT"
	CodePasswordTooLong             = "PASSWORD_TOO_LONG"
	CodeFailedToCreateUser          = "FAILED_TO_CREATE_USER"
	CodeFailedToCreateSession       = "FAILED_TO_CREATE_SESSION"
	CodeFailedToGetSession          = "FAILED_TO_GET_SESSION"
	CodeMethodNotAllowed            = "METHOD_NOT_ALLOWED"
	CodeUnauthorized                = "UNAUTHORIZED"
	CodeInternalServerError         = "INTERNAL_SERVER_ERROR"
	CodeEmailNotVerified            = "EMAIL_NOT_VERIFIED"
	CodeEmailAlreadyVerified        = "EMAIL_ALREADY_VERIFIED"
	CodeEmailMismatch               = "EMAIL_MISMATCH"
	CodeInvalidToken                = "INVALID_TOKEN"
	CodeTokenExpired                = "TOKEN_EXPIRED"
	CodeUserNotFound                = "USER_NOT_FOUND"
	CodeResetPasswordDisabled       = "RESET_PASSWORD_DISABLED"
	CodeVerificationEmailNotEnabled = "VERIFICATION_EMAIL_NOT_ENABLED"
	CodeEmailCanNotBeUpdated        = "EMAIL_CAN_NOT_BE_UPDATED"
	CodeBodyMustBeAnObject          = "BODY_MUST_BE_AN_OBJECT"
	CodeInvalidUser                 = "INVALID_USER"
	CodeFeatureNotEnabled           = "FEATURE_NOT_ENABLED"
	CodeOAuthNotImplemented         = "OAUTH_NOT_IMPLEMENTED"
	CodeSessionNotFresh             = "SESSION_NOT_FRESH"
	CodeSessionExpired              = "SESSION_EXPIRED"
	CodeChangeEmailDisabled         = "CHANGE_EMAIL_DISABLED"
	CodePasswordAlreadySet          = "PASSWORD_ALREADY_SET"
	CodeCredentialAccountNotFound   = "CREDENTIAL_ACCOUNT_NOT_FOUND"
	CodeEmailIsTheSame              = "EMAIL_IS_THE_SAME"
	CodeMissingField                = "MISSING_FIELD"
	CodeInvalidField                = "INVALID_FIELD"
	CodeDeleteUserDisabled          = "DELETE_USER_DISABLED"
	CodeProviderNotFound            = "PROVIDER_NOT_FOUND"
	CodeIDTokenNotSupported         = "ID_TOKEN_NOT_SUPPORTED"
	CodeFailedToGetUserInfo         = "FAILED_TO_GET_USER_INFO"
	CodeUserEmailNotFound           = "USER_EMAIL_NOT_FOUND"
	CodeLinkingNotAllowed           = "LINKING_NOT_ALLOWED"
	CodeLinkingDifferentEmails      = "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED"
	CodeLinkingFailed               = "LINKING_FAILED"
	CodeAccountNotFound             = "ACCOUNT_NOT_FOUND"
	CodeProviderNotSupported        = "PROVIDER_NOT_SUPPORTED"
	CodeFailedToGetAccessToken      = "FAILED_TO_GET_ACCESS_TOKEN"
	CodeTokenRefreshNotSupported    = "TOKEN_REFRESH_NOT_SUPPORTED"
	CodeRefreshTokenNotFound        = "REFRESH_TOKEN_NOT_FOUND"
	CodeFailedToRefreshAccessToken  = "FAILED_TO_REFRESH_ACCESS_TOKEN"
	CodeAccessTokenNotFound         = "ACCESS_TOKEN_NOT_FOUND"
	CodeProviderNotConfigured       = "PROVIDER_NOT_CONFIGURED"
	CodeAmbiguousAccount            = "AMBIGUOUS_ACCOUNT"
	CodeUserIDOrSessionRequired     = "USER_ID_OR_SESSION_REQUIRED"
	CodeFailedToUnlinkLastAccount   = "FAILED_TO_UNLINK_LAST_ACCOUNT"
	CodeOAuthLinkError              = "OAUTH_LINK_ERROR"
	CodeEmailPasswordSignUpDisabled = "EMAIL_PASSWORD_SIGN_UP_DISABLED"
	CodeForbidden                   = "FORBIDDEN"
	CodeInvalidUsername             = "INVALID_USERNAME"
	CodeInvalidOTP                  = "INVALID_OTP"
	CodeInvalidCode                 = "INVALID_CODE"
	CodeInvalidSIWE                 = "INVALID_SIWE"
	CodeInvalidPhone                = "INVALID_PHONE"
	CodeInvalidCredential           = "INVALID_CREDENTIAL"
	CodeInvalidDeviceCode           = "INVALID_DEVICE_CODE"
	CodeInvalidUserCode             = "INVALID_USER_CODE"
	CodeInvalidRequest              = "INVALID_REQUEST"
	CodeInvalidSlug                 = "INVALID_SLUG"
	CodeInvalidOrganization         = "INVALID_ORGANIZATION"
	CodeInvalidState                = "INVALID_STATE"
	CodeInvalidCodeOAuth            = "INVALID_CODE"
	CodeMagicLinkDisabled           = "MAGIC_LINK_DISABLED"
	CodeEmailOTPDisabled            = "EMAIL_OTP_DISABLED"
	CodePhoneOTPDisabled            = "PHONE_OTP_DISABLED"
	CodeCaptchaRequired             = "CAPTCHA_REQUIRED"
	CodeCaptchaInvalid              = "CAPTCHA_INVALID"
	CodeNotAnonymous                = "NOT_ANONYMOUS"
	CodeAnonymousSignInAgain        = "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY"
	CodeNotImpersonating            = "NOT_IMPERSONATING"
	CodeTwoFactorNotEnabled         = "TWO_FACTOR_NOT_ENABLED"
	CodeOrgNotFound                 = "ORG_NOT_FOUND"
	CodeSlugExists                  = "SLUG_EXISTS"
	CodeInvitationNotFound          = "INVITATION_NOT_FOUND"
	CodeOAuthError                  = "OAUTH_ERROR"
	CodeExpiredDeviceCode           = "EXPIRED_DEVICE_CODE"
	CodeInvalidAPIKey               = "INVALID_API_KEY"
	CodeAPIKeyNotFound              = "API_KEY_NOT_FOUND"
	CodeAPIKeyDisabled              = "API_KEY_DISABLED"
	CodeAPIKeyExpired               = "API_KEY_EXPIRED"
	CodeAccessDenied                = "ACCESS_DENIED"
	CodeAuthorizationPending        = "AUTHORIZATION_PENDING"
	CodeClientNotFound              = "CLIENT_NOT_FOUND"
	CodeExtStoreRequired            = "EXT_STORE_REQUIRED"
)

// API error messages.
const (
	MsgInvalidEmail                 = "Invalid email"
	MsgInvalidPassword              = "Invalid password"
	MsgInvalidEmailOrPassword       = "Invalid email or password"
	MsgPasswordTooShort             = "Password is too short"
	MsgPasswordTooLong              = "Password is too long"
	MsgFailedToCreateUser           = "Failed to create user"
	MsgFailedToCreateSession        = "Failed to create session"
	MsgFailedToGetSession           = "Failed to get session"
	MsgMethodNotAllowed             = "POST get-session requires deferSessionRefresh"
	MsgUnauthorized                 = "Unauthorized"
	MsgInternalServerError          = "Internal server error"
	MsgEmailNotVerified             = "Email not verified"
	MsgEmailAlreadyVerified         = "Email is already verified"
	MsgEmailMismatch                = "Email mismatch"
	MsgInvalidToken                 = "Invalid token"
	MsgTokenExpired                 = "Session expired. Re-authenticate to perform this action."
	MsgUserNotFound                 = "User not found"
	MsgResetPasswordDisabled        = "Reset password isn't enabled"
	MsgVerificationEmailNotEnabled  = "Verification email isn't enabled"
	MsgEmailCanNotBeUpdated         = "Email can not be updated"
	MsgBodyMustBeAnObject           = "Body must be an object"
	MsgNoFieldsToUpdate             = "No fields to update"
	MsgInvalidUser                  = "Invalid user"
	MsgFeatureNotEnabled            = "Feature not enabled"
	MsgOAuthNotImplemented          = "OAuth not implemented"
	MsgSessionNotFresh              = "Session is not fresh"
	MsgSessionExpired               = "Session expired"
	MsgChangeEmailDisabled          = "Change email is disabled"
	MsgPasswordAlreadySet           = "Password already set"
	MsgCredentialAccountNotFound    = "Credential account not found"
	MsgEmailIsTheSame               = "Email is the same"
	MsgMissingField                 = "is required"
	MsgInvalidField                 = "Invalid field"
	MsgDeleteUserDisabled           = "Not found"
	MsgProviderNotFound             = "Provider not found"
	MsgIDTokenNotSupported          = "ID token not supported"
	MsgFailedToGetUserInfo          = "Failed to get user info"
	MsgUserEmailNotFound            = "User email not found"
	MsgLinkingNotAllowed            = "Linking not allowed"
	MsgLinkingDifferentEmails       = "Linking different emails not allowed"
	MsgLinkingFailed                = "Linking failed"
	MsgAccountNotFound              = "Account not found"
	MsgProviderNotSupported         = "Provider not supported"
	MsgFailedToGetAccessToken       = "Failed to get access token"
	MsgTokenRefreshNotSupported     = "Token refresh not supported"
	MsgRefreshTokenNotFound         = "Refresh token not found"
	MsgFailedToRefreshAccessToken   = "Failed to refresh access token"
	MsgAccessTokenNotFound          = "Access token not found"
	MsgProviderNotConfigured        = "Provider not configured"
	MsgAmbiguousAccount             = "Ambiguous account"
	MsgFailedToUnlinkLastAccount    = "Failed to unlink last account"
	MsgOAuthLinkError               = "OAuth link error"
	MsgEmailPasswordSignUpDisabled  = "Email and password sign up is not enabled"
	MsgInvalidRequestBody           = "Invalid request body"
	MsgNameRequired                 = "Name is required"
	MsgForbidden                    = "Admin access required"
	MsgInvalidUsername              = "Invalid username"
	MsgInvalidCredentials           = "Invalid credentials"
	MsgInvalidOTP                   = "Invalid OTP"
	MsgInvalidCode                  = "Invalid code"
	MsgInvalidSIWE                  = "Invalid SIWE payload"
	MsgInvalidSIWEMessage           = "Invalid message"
	MsgInvalidPhone                 = "Invalid phone number"
	MsgInvalidCredential            = "Invalid credential"
	MsgInvalidDeviceCode            = "Invalid device code"
	MsgInvalidUserCode              = "Invalid user code"
	MsgInvalidRequest               = "Invalid request"
	MsgInvalidSlug                  = "Invalid slug"
	MsgInvalidOrganization          = "Invalid organization"
	MsgInvalidState                 = "Invalid state"
	MsgInvalidTokenRequest          = "Invalid token request"
	MsgMagicLinkDisabled            = "Magic link is not configured"
	MsgEmailOTPDisabled             = "Email OTP not configured"
	MsgPhoneOTPDisabled             = "Phone OTP not configured"
	MsgCaptchaRequired              = "Captcha token required"
	MsgCaptchaInvalid               = "Invalid captcha"
	MsgNotAnonymous                 = "User is not anonymous"
	MsgAnonymousSignInAgain         = "Anonymous users cannot sign in again anonymously"
	MsgNotImpersonating             = "Not impersonating"
	MsgTwoFactorNotEnabled          = "2FA not enabled"
	MsgFailedToGenerateTOTP         = "Failed to generate TOTP"
	MsgOrgNotFound                  = "Organization not found"
	MsgSlugExists                   = "Slug already exists"
	MsgInvitationNotFound           = "Invitation not found"
	MsgOAuthError                   = "Invalid OAuth callback"
	MsgExpiredDeviceCode            = "Device code expired"
	MsgInvalidAPIKey                = "Invalid API key"
	MsgAPIKeyNotFound               = "API key not found"
	MsgAPIKeyDisabled               = "API key is disabled"
	MsgAPIKeyExpired                = "API key has expired"
	MsgAccessDenied                 = "Access denied"
	MsgAuthorizationPending         = "Authorization pending"
	MsgClientNotFound               = "Client not found"
	MsgExtStoreRequired             = "ExtStore required"
	MsgPasswordBreach               = "password has been found in a data breach"
	MsgResetPasswordIfExists        = "If this email exists in our system, check your email for the reset link"
	MsgOK                           = "OK"
	MsgCannotUnlinkLastAccount      = "Cannot unlink last account"
	MsgProviderIsNotSupported       = "Provider is not supported"
	MsgProviderNoTokenRefresh       = "Provider does not support token refreshing"
	MsgAmbiguousAccountDetail       = "Multiple accounts share this account ID. Pass a providerId to disambiguate."
	MsgProviderNotConfiguredAcct    = "Account is not associated with a configured social provider"
	MsgIDTokenNotSupportedDetail    = "Provider does not support id token verification"
	MsgOAuthNotImplementedProvider  = "OAuth not implemented for provider"
	MsgUserIDOrSessionRequired      = "Either userId or session is required"
	MsgFailedValidAccessToken       = "Failed to get a valid access token"
	MsgLinkingNotAllowedDetail      = "Account not linked - linking not allowed"
	MsgLinkingDifferentEmailsDetail = "Account not linked - different emails not allowed"
	MsgLinkingFailedDetail          = "Account not linked - unable to create account"
)

// Internal / sentinel error messages (non-API).
const (
	ErrMsgNotFound               = "not found"
	ErrMsgAlreadyExists          = "already exists"
	ErrMsgSecretRequired         = "betterauth: Secret is required"
	ErrMsgStoreRequired          = "betterauth: Store is required"
	ErrMsgTokenExpired           = "token expired"
	ErrMsgTokenInvalid           = "invalid token"
	ErrMsgInvalidHashFormat      = "invalid hash format"
	ErrMsgInvalidSessionCacheEnc = "invalid session cache encoding"
	ErrMsgInvalidSessionCachePay = "invalid session cache payload"
	ErrMsgInvalidSessionCacheSig = "invalid session cache signature"
	ErrMsgSessionCacheVersion    = "session cache version mismatch"
	ErrMsgMissingEmailClaim      = "missing email claim"
	ErrMsgHashFail               = "hash fail"
	ErrMsgInjected               = "injected"
	ErrMsgSmtpDown               = "smtp down"
)

// APIMessage returns the default message for an API error code.
func APIMessage(code string) string {
	if msg, ok := apiMessages[code]; ok {
		return msg
	}
	return MsgInternalServerError
}

var apiMessages = map[string]string{
	CodeInvalidEmail:                MsgInvalidEmail,
	CodeInvalidPassword:             MsgInvalidPassword,
	CodeInvalidEmailOrPassword:      MsgInvalidEmailOrPassword,
	CodePasswordTooShort:            MsgPasswordTooShort,
	CodePasswordTooLong:             MsgPasswordTooLong,
	CodeFailedToCreateUser:          MsgFailedToCreateUser,
	CodeFailedToCreateSession:       MsgFailedToCreateSession,
	CodeFailedToGetSession:          MsgFailedToGetSession,
	CodeMethodNotAllowed:            MsgMethodNotAllowed,
	CodeUnauthorized:                MsgUnauthorized,
	CodeInternalServerError:         MsgInternalServerError,
	CodeEmailNotVerified:            MsgEmailNotVerified,
	CodeEmailAlreadyVerified:        MsgEmailAlreadyVerified,
	CodeEmailMismatch:               MsgEmailMismatch,
	CodeInvalidToken:                MsgInvalidToken,
	CodeTokenExpired:                MsgTokenExpired,
	CodeUserNotFound:                MsgUserNotFound,
	CodeResetPasswordDisabled:       MsgResetPasswordDisabled,
	CodeVerificationEmailNotEnabled: MsgVerificationEmailNotEnabled,
	CodeEmailCanNotBeUpdated:        MsgEmailCanNotBeUpdated,
	CodeBodyMustBeAnObject:          MsgBodyMustBeAnObject,
	CodeInvalidUser:                 MsgInvalidUser,
	CodeFeatureNotEnabled:           MsgFeatureNotEnabled,
	CodeOAuthNotImplemented:         MsgOAuthNotImplemented,
	CodeSessionNotFresh:             MsgSessionNotFresh,
	CodeSessionExpired:              MsgSessionExpired,
	CodeChangeEmailDisabled:         MsgChangeEmailDisabled,
	CodePasswordAlreadySet:          MsgPasswordAlreadySet,
	CodeCredentialAccountNotFound:   MsgCredentialAccountNotFound,
	CodeEmailIsTheSame:              MsgEmailIsTheSame,
	CodeMissingField:                MsgMissingField,
	CodeInvalidField:                MsgInvalidField,
	CodeDeleteUserDisabled:          MsgDeleteUserDisabled,
	CodeProviderNotFound:            MsgProviderNotFound,
	CodeIDTokenNotSupported:         MsgIDTokenNotSupported,
	CodeFailedToGetUserInfo:         MsgFailedToGetUserInfo,
	CodeUserEmailNotFound:           MsgUserEmailNotFound,
	CodeLinkingNotAllowed:           MsgLinkingNotAllowed,
	CodeLinkingDifferentEmails:      MsgLinkingDifferentEmails,
	CodeLinkingFailed:               MsgLinkingFailed,
	CodeAccountNotFound:             MsgAccountNotFound,
	CodeProviderNotSupported:        MsgProviderNotSupported,
	CodeFailedToGetAccessToken:      MsgFailedToGetAccessToken,
	CodeTokenRefreshNotSupported:    MsgTokenRefreshNotSupported,
	CodeRefreshTokenNotFound:        MsgRefreshTokenNotFound,
	CodeFailedToRefreshAccessToken:  MsgFailedToRefreshAccessToken,
	CodeAccessTokenNotFound:         MsgAccessTokenNotFound,
	CodeProviderNotConfigured:       MsgProviderNotConfigured,
	CodeAmbiguousAccount:            MsgAmbiguousAccount,
	CodeUserIDOrSessionRequired:     MsgUserIDOrSessionRequired,
	CodeFailedToUnlinkLastAccount:   MsgFailedToUnlinkLastAccount,
	CodeOAuthLinkError:              MsgOAuthLinkError,
	CodeEmailPasswordSignUpDisabled: MsgEmailPasswordSignUpDisabled,
	CodeForbidden:                   MsgForbidden,
	CodeInvalidUsername:             MsgInvalidUsername,
	CodeInvalidOTP:                  MsgInvalidOTP,
	CodeInvalidCode:                 MsgInvalidCode,
	CodeInvalidSIWE:                 MsgInvalidSIWE,
	CodeInvalidPhone:                MsgInvalidPhone,
	CodeInvalidCredential:           MsgInvalidCredential,
	CodeInvalidDeviceCode:           MsgInvalidDeviceCode,
	CodeInvalidUserCode:             MsgInvalidUserCode,
	CodeInvalidRequest:              MsgInvalidRequest,
	CodeInvalidSlug:                 MsgInvalidSlug,
	CodeInvalidOrganization:         MsgInvalidOrganization,
	CodeInvalidState:                MsgInvalidState,
	CodeMagicLinkDisabled:           MsgMagicLinkDisabled,
	CodeEmailOTPDisabled:            MsgEmailOTPDisabled,
	CodePhoneOTPDisabled:            MsgPhoneOTPDisabled,
	CodeCaptchaRequired:             MsgCaptchaRequired,
	CodeCaptchaInvalid:              MsgCaptchaInvalid,
	CodeNotAnonymous:                MsgNotAnonymous,
	CodeAnonymousSignInAgain:        MsgAnonymousSignInAgain,
	CodeNotImpersonating:            MsgNotImpersonating,
	CodeTwoFactorNotEnabled:         MsgTwoFactorNotEnabled,
	CodeOrgNotFound:                 MsgOrgNotFound,
	CodeSlugExists:                  MsgSlugExists,
	CodeInvitationNotFound:          MsgInvitationNotFound,
	CodeOAuthError:                  MsgOAuthError,
	CodeExpiredDeviceCode:           MsgExpiredDeviceCode,
	CodeInvalidAPIKey:               MsgInvalidAPIKey,
	CodeAPIKeyNotFound:              MsgAPIKeyNotFound,
	CodeAPIKeyDisabled:              MsgAPIKeyDisabled,
	CodeAPIKeyExpired:               MsgAPIKeyExpired,
	CodeAccessDenied:                MsgAccessDenied,
	CodeAuthorizationPending:        MsgAuthorizationPending,
	CodeClientNotFound:              MsgClientNotFound,
	CodeExtStoreRequired:            MsgExtStoreRequired,
}
