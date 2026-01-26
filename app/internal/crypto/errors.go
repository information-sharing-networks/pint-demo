package crypto

import "fmt"

// Error represents a structured error from the crypto package
type Error interface {
	error
	Code() ErrorCode
	Unwrap() error
}

type ErrorCode string

const (
	ErrCodeValidation       ErrorCode = "validation"
	ErrCodeInvalidChecksum  ErrorCode = "invalid_checksum"
	ErrCodeInvalidSignature ErrorCode = "invalid_signature"
	ErrCodeCertificate      ErrorCode = "certificate"
	ErrCodeKeyManagement    ErrorCode = "key_management"
	ErrCodeInternal         ErrorCode = "internal"
)

// CryptoError represents a structured error from the crypto package
type CryptoError struct {

	// code is the cryptoerror code
	code ErrorCode

	// message is a human-readable error message
	message string

	// wrapped is the optional underlying error
	wrapped error
}

func (e *CryptoError) Error() string {
	if e.wrapped != nil {
		return fmt.Sprintf("%s: %v", e.message, e.wrapped)
	}
	return e.message
}

func (e *CryptoError) Code() ErrorCode { return e.code }
func (e *CryptoError) Unwrap() error   { return e.wrapped }

// NewValidationError creates a validation error for invalid input.
// Use this for errors related to missing required fields, bad format,
// invalid JSON, bad encoding, or unsupported algorithms.
//
// The returned error will have code ErrCodeValidation.
func NewValidationError(msg string) error {
	return &CryptoError{code: ErrCodeValidation, message: msg}
}

// WrapValidationError wraps an existing error as a validation error.
// Use this for errors related to missing required fields, bad format,
// invalid JSON, bad encoding, or unsupported algorithms.
//
// The returned error will have code ErrCodeValidation.
func WrapValidationError(err error, msg string) error {
	return &CryptoError{code: ErrCodeValidation, message: msg, wrapped: err}
}

// NewChecksumError creates a checksum verification error.
// Use this for errors related to checksum mismatches or invalid checksum formats.
//
// The returned error will have code ErrCodeInvalidChecksum.
func NewChecksumError(msg string) error {
	return &CryptoError{code: ErrCodeInvalidChecksum, message: msg}
}

// WrapChecksumError wraps an existing error as a checksum error,
// Use this for errors related to checksum mismatches or invalid checksum formats.
//
// The returned error will have code ErrCodeInvalidChecksum.
func WrapChecksumError(err error, msg string) error {
	return &CryptoError{code: ErrCodeInvalidChecksum, message: msg, wrapped: err}
}

// NewSignatureError creates a signature verification error.
// Use this for errors related to signature verification failures or malformed signatures.
//
// The returned error will have code ErrCodeInvalidSignature.
func NewSignatureError(msg string) error {
	return &CryptoError{code: ErrCodeInvalidSignature, message: msg}
}

// WrapSignatureError wraps an existing error as a signature error.
// Use this for errors related to signature verification failures or malformed signatures.
//
// The returned error will have code ErrCodeInvalidSignature.
func WrapSignatureError(err error, msg string) error {
	return &CryptoError{code: ErrCodeInvalidSignature, message: msg, wrapped: err}
}

// NewCertificateError creates a certificate validation error.
// Use this for errors related to expired certificates, untrusted CAs,
// or certificate chain validation failures.
//
// The returned error will have code ErrCodeCertificate.
func NewCertificateError(msg string) error {
	return &CryptoError{code: ErrCodeCertificate, message: msg}
}

// WrapCertificateError wraps an existing error as a certificate error.
// Use this for errors related to expired certificates, untrusted CAs,
// or certificate chain validation failures.
//
// The returned error will have code ErrCodeCertificate.
func WrapCertificateError(err error, msg string) error {
	return &CryptoError{code: ErrCodeCertificate, message: msg, wrapped: err}
}

// NewKeyManagementError creates a key management error.
// Use this for errors related to key loading, key generation, key not found,
// invalid key format, or JWK parsing failures.
//
// The returned error will have code ErrCodeKeyManagement.
func NewKeyManagementError(msg string) error {
	return &CryptoError{code: ErrCodeKeyManagement, message: msg}
}

// WrapKeyManagementError wraps an existing error as a key management error,
// Use this for errors related to key loading, key generation, key not found,
// invalid key format, or JWK parsing failures.
//
// The returned error will have code ErrCodeKeyManagement.
func WrapKeyManagementError(err error, msg string) error {
	return &CryptoError{code: ErrCodeKeyManagement, message: msg, wrapped: err}
}

// NewInternalError creates an internal error for unexpected failures.
// Use this for errors related to crypto library failures, unexpected nil values,
// or system errors that should not normally occur.
//
// The returned error will have code ErrCodeInternal.
func NewInternalError(msg string) error {
	return &CryptoError{code: ErrCodeInternal, message: msg}
}

// WrapInternalError wraps an existing error as an internal error.
// Use this for errors related to crypto library failures, unexpected nil values,
// or system errors that should not normally occur.
//
// The returned error will have code ErrCodeInternal.
func WrapInternalError(err error, msg string) error {
	return &CryptoError{code: ErrCodeInternal, message: msg, wrapped: err}
}
