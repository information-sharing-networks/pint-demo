package pint

// errors.go defines the error codes used by the PINT API

import "fmt"

// PintError represents a structured error from the pint package.
type PintError struct {
	// code is the PINT error code
	code ErrorCode

	// message is a human-readable error message
	message string

	// wrapped is the optional underlying error
	wrapped error
}

func (e *PintError) Error() string {
	if e.wrapped != nil {
		return fmt.Sprintf("%s: %v", e.message, e.wrapped)
	}
	return e.message
}

func (e *PintError) Code() ErrorCode { return e.code }
func (e *PintError) Unwrap() error   { return e.wrapped }

// ErrorCode is used in errors returned by the PINT API.
//
// Note: The DCSA does not standardize specific error codes, but suggests the following ranges:
//
//   - 7000-7999 for technical errors - used when it is not possible to process a request due to a technical issue with the supplied data.
//   - 8000-8999 for functional errors -  used when the request is technically valid but there is a business logic reason preventing the request from being processed.
//
// c.f https://developer.dcsa.org/standard-error-codes
type ErrorCode int

// Error codes used by this implementation of the PINT API
const (

	// ErrCodeBadSignature is used when a JWS signature verification fails (e.g. invalid signature, wrong key, etc)
	ErrCodeBadSignature ErrorCode = 7001

	// ErrCodeBadCertificate: x5c certificates can optionally be included in a JWS to provide non-repudiation
	// This error code is used when the certificate is present but the validation fails for some reason.
	ErrCodeBadCertificate ErrorCode = 7002

	// ErrCodeBadChecksum is used when a document checksum does not match the expected value
	// checksums are used to ensure the integrity of the transport document, supporting documents and the transfer chain.
	ErrCodeBadChecksum ErrorCode = 7003

	// ErrCodeInvalidEnvelope is used when the envelope structure or validation fails
	// this includes missing required fields, invalid format, etc.
	ErrCodeInvalidEnvelope ErrorCode = 7004

	// ErrCodeInternalError is used when an internal server error occurs
	ErrCodeInternalError ErrorCode = 7005

	// ErrCodeMalformedRequest is used when JSON parsing or encoding fails
	ErrCodeMalformedRequest ErrorCode = 7006 // JSON parsing or encoding failed

	// ErrCodeKeyError is used when there is a problem with the signing key
	// (e.g. when the key is not found in the key store, or the key is not valid for the requested operation)
	ErrCodeKeyError ErrorCode = 7007

	// ErrCodeRegistryError is used when there is a problem with the DCSA registry
	ErrCodeRegistryError ErrorCode = 7008

	// ErrCodeRateLimitExceeded is used when the rate limit is exceeded
	// - this is only used in the middleware
	ErrCodeRateLimitExceeded ErrorCode = 7009

	// ErrCodeRequestTooLarge is used when the request body is too large
	// - this is only used in the middleware
	ErrCodeRequestTooLarge ErrorCode = 7010

	// ErrCodeUnknownParty is used when a platform is not recognized or not registered
	ErrCodeUnknownParty ErrorCode = 8001

	// ErrCodeInsufficientTrust is used when the trust level of a signature is below the minimum required
	// c.f trust_level.go for more information on trust levels
	ErrCodeInsufficientTrust ErrorCode = 8002 // Trust level below minimum required
)

// NewMalformedRequestError creates an error for malformed requests.
func NewMalformedRequestError(msg string) error {
	return &PintError{code: ErrCodeMalformedRequest, message: msg}
}

// WrapMalformedRequestError wraps an existing error as a malformed request error.
func WrapMalformedRequestError(err error, msg string) error {
	return &PintError{code: ErrCodeMalformedRequest, message: msg, wrapped: err}
}

// NewKeyError creates a key management error.
// Use this for errors related to key loading, key not found, invalid key format,
// or JWK parsing failures in the PINT context.
//
// The returned error will have code ErrCodeKeyError.
func NewKeyError(msg string) error {
	return &PintError{code: ErrCodeKeyError, message: msg}
}

// WrapKeyError wraps an existing error as a key management error.
// Use this for errors related to key loading, key not found, invalid key format,
// or JWK parsing failures in the PINT context.
//
// The returned error will have code ErrCodeKeyError.
func WrapKeyError(err error, msg string) error {
	return &PintError{code: ErrCodeKeyError, message: msg, wrapped: err}
}

// NewRegistryError creates a DCSA registry error.
// Use this for errors related to unknown platforms, invalid registry format,
// or registry loading failures.
//
// The returned error will have code ErrCodeRegistryError.
func NewRegistryError(msg string) error {
	return &PintError{code: ErrCodeRegistryError, message: msg}
}

// WrapRegistryError wraps an existing error as a DCSA registry error.
// Use this for errors related to unknown platforms, invalid registry format,
// or registry loading failures.
//
// The returned error will have code ErrCodeUnknownParty.
func WrapRegistryError(err error, msg string) error {
	return &PintError{code: ErrCodeRegistryError, message: msg, wrapped: err}
}

// NewValidationError creates a validation error for invalid input.
// Use this for errors related to missing required fields, bad format,
// invalid JSON, or bad configuration in the PINT context.
//
// The returned error will have code ErrCodeInvalidEnvelope.
func NewValidationError(msg string) error {
	return &PintError{code: ErrCodeInvalidEnvelope, message: msg}
}

// WrapValidationError wraps an existing error as a validation error.
// Use this for errors related to missing required fields, bad format,
// invalid JSON, or bad configuration in the PINT context.
//
// The returned error will have code ErrCodeInvalidEnvelope.
func WrapValidationError(err error, msg string) error {
	return &PintError{code: ErrCodeInvalidEnvelope, message: msg, wrapped: err}
}

// NewInternalError creates an internal error for unexpected failures.
// Use this for errors related to unexpected nil values, system errors,
// or other failures that should not normally occur in the PINT context.
//
// The returned error will have code ErrCodeInternalError.
func NewInternalError(msg string) error {
	return &PintError{code: ErrCodeInternalError, message: msg}
}

// WrapInternalError wraps an existing error as an internal error.
// Use this for errors related to unexpected nil values, system errors,
// or other failures that should not normally occur in the PINT context.
//
// The returned error will have code ErrCodeInternalError.
func WrapInternalError(err error, msg string) error {
	return &PintError{code: ErrCodeInternalError, message: msg, wrapped: err}
}

// NewRateLimitError creates a rate limit exceeded error.
// Use this when the client has exceeded the rate limit.
//
// The returned error will have code ErrCodeRateLimitExceeded.
func NewRateLimitError(msg string) error {
	return &PintError{code: ErrCodeRateLimitExceeded, message: msg}
}

// NewRequestTooLargeError creates a request too large error.
// Use this when the request body exceeds the maximum allowed size.
//
// The returned error will have code ErrCodeRequestTooLarge.
func NewRequestTooLargeError(msg string) error {
	return &PintError{code: ErrCodeRequestTooLarge, message: msg}
}
