package apierror

import (
	"encoding/json"
	"net/http"

	"github.com/patrickkabwe/betterauth-go/constants"
)

// Error represents a Better Auth API error response.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"-"`
}

func (e *Error) Error() string { return e.Message }

// Error code aliases (backward compatible).
const (
	CodeInvalidEmail                = constants.CodeInvalidEmail
	CodeInvalidPassword             = constants.CodeInvalidPassword
	CodeInvalidEmailOrPassword      = constants.CodeInvalidEmailOrPassword
	CodePasswordTooShort            = constants.CodePasswordTooShort
	CodePasswordTooLong             = constants.CodePasswordTooLong
	CodeFailedToCreateUser          = constants.CodeFailedToCreateUser
	CodeFailedToCreateSession       = constants.CodeFailedToCreateSession
	CodeMethodNotAllowed            = constants.CodeMethodNotAllowed
	CodeUnauthorized                = constants.CodeUnauthorized
	CodeInternalServerError         = constants.CodeInternalServerError
	CodeEmailNotVerified            = constants.CodeEmailNotVerified
	CodeInvalidToken                = constants.CodeInvalidToken
	CodeTokenExpired                = constants.CodeTokenExpired
	CodeUserNotFound                = constants.CodeUserNotFound
	CodeResetPasswordDisabled       = constants.CodeResetPasswordDisabled
	CodeVerificationEmailNotEnabled = constants.CodeVerificationEmailNotEnabled
	CodeEmailCanNotBeUpdated        = constants.CodeEmailCanNotBeUpdated
	CodeBodyMustBeAnObject          = constants.CodeBodyMustBeAnObject
	CodeInvalidUser                 = constants.CodeInvalidUser
	CodeFeatureNotEnabled           = constants.CodeFeatureNotEnabled
	CodeOAuthNotImplemented         = constants.CodeOAuthNotImplemented
	CodeSessionNotFresh             = constants.CodeSessionNotFresh
	CodeSessionExpired              = constants.CodeSessionExpired
	CodeChangeEmailDisabled         = constants.CodeChangeEmailDisabled
	CodePasswordAlreadySet          = constants.CodePasswordAlreadySet
	CodeCredentialAccountNotFound   = constants.CodeCredentialAccountNotFound
	CodeEmailIsTheSame              = constants.CodeEmailIsTheSame
	CodeMissingField                = constants.CodeMissingField
	CodeInvalidField                = constants.CodeInvalidField
	CodeDeleteUserDisabled          = constants.CodeDeleteUserDisabled
	CodeProviderNotFound            = constants.CodeProviderNotFound
	CodeIDTokenNotSupported         = constants.CodeIDTokenNotSupported
	CodeFailedToGetUserInfo         = constants.CodeFailedToGetUserInfo
	CodeUserEmailNotFound           = constants.CodeUserEmailNotFound
	CodeLinkingNotAllowed           = constants.CodeLinkingNotAllowed
	CodeLinkingDifferentEmails      = constants.CodeLinkingDifferentEmails
	CodeLinkingFailed               = constants.CodeLinkingFailed
	CodeAccountNotFound             = constants.CodeAccountNotFound
	CodeProviderNotSupported        = constants.CodeProviderNotSupported
	CodeFailedToGetAccessToken      = constants.CodeFailedToGetAccessToken
	CodeTokenRefreshNotSupported    = constants.CodeTokenRefreshNotSupported
	CodeRefreshTokenNotFound        = constants.CodeRefreshTokenNotFound
	CodeFailedToRefreshAccessToken  = constants.CodeFailedToRefreshAccessToken
	CodeAccessTokenNotFound         = constants.CodeAccessTokenNotFound
	CodeProviderNotConfigured       = constants.CodeProviderNotConfigured
	CodeAmbiguousAccount            = constants.CodeAmbiguousAccount
	CodeUserIDOrSessionRequired     = constants.CodeUserIDOrSessionRequired
	CodeFailedToUnlinkLastAccount   = constants.CodeFailedToUnlinkLastAccount
	CodeOAuthLinkError              = constants.CodeOAuthLinkError
)

// New creates an API error with an explicit message.
func New(status int, code, message string) *Error {
	return &Error{Status: status, Code: code, Message: message}
}

// WithCode creates an API error using the default message for code.
func WithCode(status int, code string) *Error {
	return New(status, code, constants.APIMessage(code))
}

func WriteJSON(w http.ResponseWriter, err *Error) {
	w.Header().Set(constants.HeaderContentType, constants.MIMEJSON)
	w.WriteHeader(err.Status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"code":    err.Code,
		"message": err.Message,
	})
}
