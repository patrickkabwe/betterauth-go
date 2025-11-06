package errors

import (
	stderrors "errors"

	"github.com/patrickkabwe/betterauth-go/constants"
)

// Store errors.
var (
	ErrNotFound      = stderrors.New(constants.ErrMsgNotFound)
	ErrAlreadyExists = stderrors.New(constants.ErrMsgAlreadyExists)
)

// Configuration errors.
var (
	ErrSecretRequired = stderrors.New(constants.ErrMsgSecretRequired)
	ErrStoreRequired  = stderrors.New(constants.ErrMsgStoreRequired)
)

// JWT errors.
var (
	ErrTokenExpired = stderrors.New(constants.ErrMsgTokenExpired)
	ErrTokenInvalid = stderrors.New(constants.ErrMsgTokenInvalid)
)

// Crypto errors.
var (
	ErrInvalidHashFormat = stderrors.New(constants.ErrMsgInvalidHashFormat)
)

// Session cache errors.
var (
	ErrInvalidSessionCacheEncoding = stderrors.New(constants.ErrMsgInvalidSessionCacheEnc)
	ErrInvalidSessionCachePayload  = stderrors.New(constants.ErrMsgInvalidSessionCachePay)
	ErrInvalidSessionCacheSig      = stderrors.New(constants.ErrMsgInvalidSessionCacheSig)
	ErrSessionCacheVersionMismatch = stderrors.New(constants.ErrMsgSessionCacheVersion)
)

// Auth flow errors.
var (
	ErrMissingEmailClaim = stderrors.New(constants.ErrMsgMissingEmailClaim)
)

// Test-only errors.
var (
	ErrInjected = stderrors.New(constants.ErrMsgInjected)
	ErrHashFail = stderrors.New(constants.ErrMsgHashFail)
	ErrSmtpDown = stderrors.New(constants.ErrMsgSmtpDown)
)
