package ebl

import (
	"fmt"
)

// Error represents a structured error from the ebl package.
type Error interface {
	error
	Code() ErrorCode
	Unwrap() error
}

type ErrorCode string

const (
	// ErrCodeSignature indicates signature verification or trust level failures.
	ErrCodeSignature ErrorCode = "BSIG" // bad signature

	// ErrCodeEnvelope indicates envelope integrity, validation, or processing failures.
	ErrCodeEnvelope ErrorCode = "BENV" // bad envelope

	// ErrCodeIssuanceBadRequest indicates that the issuance request is invalid.
	ErrCodeIssuanceBadRequest ErrorCode = "BREQ"

	// ErrCodeIssuanceRefused indicates that the issuance request is valid but the eBL platform cannot issue the eBL.
	ErrCodeIssuanceRefused ErrorCode = "REFU"

	// ErrCodeInternal indicates internal processing failures.
	ErrCodeInternal ErrorCode = "INT" // internal error
)

// EblError represents a structured error from the ebl package.
type EblError struct {
	// code is the error code
	code ErrorCode

	// message is a human-readable error message
	message string

	// wrapped is the optional underlying error
	wrapped error
}

func (e *EblError) Error() string {
	if e.wrapped != nil {
		return fmt.Sprintf("%s: %s: %v", e.code, e.message, e.wrapped)
	}
	return fmt.Sprintf("%s: %s", e.code, e.message)
}

func (e *EblError) Code() ErrorCode { return e.code }
func (e *EblError) Unwrap() error   { return e.wrapped }

// NewSignatureError creates a signature verification error.
// Use this for errors related to JWS signature verification failures,
// x5c certificate validation failures, or trust level determination failures.
func NewSignatureError(msg string) error {
	return &EblError{code: ErrCodeSignature, message: msg}
}

// WrapSignatureError wraps an existing error as a signature error,
// adding context while preserving the original error for inspection.
// Use this for errors related to JWS signature verification failures,
// x5c certificate validation failures, or trust level determination failures.
func WrapSignatureError(err error, msg string) error {
	return &EblError{code: ErrCodeSignature, message: msg, wrapped: err}
}

// NewEnvelopeError creates an envelope error for any non-signature technical failure.
// Use this for errors related to missing fields, invalid format, invalid checksums, etc.
//
// Maps to DCSA "BENV" (Bad Envelope) response code.
func NewEnvelopeError(msg string) error {
	return &EblError{code: ErrCodeEnvelope, message: msg}
}

// NewEnvelopeError creates an envelope error for any non-signature technical failure.
// Use this for errors related to missing fields, invalid format, invalid checksums, etc.
//
// Maps to DCSA "BENV" (Bad Envelope) response code.
func WrapEnvelopeError(err error, msg string) error {
	return &EblError{code: ErrCodeEnvelope, message: msg, wrapped: err}
}

// NewIssuanceBadRequestError creates an issuance bad request error.
func NewIssuanceBadRequestError(msg string) error {
	return &EblError{code: ErrCodeIssuanceBadRequest, message: msg}
}

// WrapIssuanceBadRequestError wraps an existing error as an issuance bad request error.
func WrapIssuanceBadRequestError(err error, msg string) error {
	return &EblError{code: ErrCodeIssuanceBadRequest, message: msg, wrapped: err}
}

// NewIssuanceRefusedError creates an issuance refused error.
func NewIssuanceRefusedError(msg string) error {
	return &EblError{code: ErrCodeIssuanceRefused, message: msg}
}

// NewInternalError creates an internal error for unexpected failures.
func NewInternalError(msg string) error {
	return &EblError{code: ErrCodeInternal, message: msg}
}

// WrapInternalError wraps an existing error as an internal error.
func WrapInternalError(err error, msg string) error {
	return &EblError{code: ErrCodeInternal, message: msg, wrapped: err}
}
