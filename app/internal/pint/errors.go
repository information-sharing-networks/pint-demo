package pint

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/information-sharing-networks/pint-demo/app/internal/ebl"
)

// ErrorCode is used in errors returned by the PINT API.
//
// Note: The DCSA specification does not standardize specific error codes, but suggests the following ranges:
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

	// ErrCodeMalformedJSON is used when JSON parsing or encoding fails
	ErrCodeMalformedJSON ErrorCode = 7006 // JSON parsing or encoding failed

	// ErrCodeKeyError is used when there is a problem with the signing key
	// (e.g. when the key is not found in the key store, or the key is not valid for the requested operation)
	ErrCodeKeyError ErrorCode = 7007

	// ErrCodeUnknownParty is used when a party is not recognized or not registered
	ErrCodeUnknownParty ErrorCode = 8001

	// ErrCodeInsufficientTrust is used when the trust level of a signature is below the minimum required
	// c.f trust_level.go for more information on trust levels
	ErrCodeInsufficientTrust ErrorCode = 8002 // Trust level below minimum required
)

// ErrorResponse represents the DCSA standard error response format
type ErrorResponse struct {

	// The HTTP method used to make the request e.g. GET, POST, etc
	HTTPMethod string `json:"httpMethod"`

	// The URI that was requested
	RequestURI string `json:"requestUri"`

	// The HTTP status code returned
	StatusCode int `json:"statusCode"`

	// A standard short description corresponding to the HTTP status code
	StatusCodeText string `json:"statusCodeText"`

	// A long description corresponding to the HTTP status code with additional information
	StatusCodeMessage string `json:"statusCodeMessage,omitempty"`

	// A unique identifier to the HTTP request within the scope of the API provider
	ProviderCorrelationReference string `json:"providerCorrelationReference,omitempty"`

	// The DateTime corresponding to the error occurring
	ErrorDateTime string `json:"errorDateTime"`

	// An array of errors providing more detail about the root cause
	Errors []DetailedError `json:"errors"`
}

// DetailedError represents a detailed error in the DCSA error response
type DetailedError struct {
	// A standard error code see https://developer.dcsa.org/standard-error-codes
	ErrorCode        ErrorCode `json:"errorCode"`
	Property         string    `json:"property,omitempty"`
	Value            string    `json:"value,omitempty"`
	JSONPath         string    `json:"jsonPath,omitempty"`
	ErrorCodeText    string    `json:"errorCodeText"`
	ErrorCodeMessage string    `json:"errorCodeMessage"`
}

// MapErrorToResponse maps ebl.Error, crypto.Error, or generic errors to a DCSA error response.
// call this function when you want to convert an error into a DCSA error response.
func MapErrorToResponse(err error, r *http.Request) *ErrorResponse {
	requestID := middleware.GetReqID(r.Context())

	// Try to extract the most specific error type first (crypto.Error)
	var cryptoErr *crypto.CryptoError
	if errors.As(err, &cryptoErr) {
		return errorResponseFromCrypto(cryptoErr, r, requestID)
	}

	// Then try ebl.Error (non-crypto ebl package errors)
	var eblErr *ebl.EblError
	if errors.As(err, &eblErr) {
		return errorResponseFromEbl(eblErr, r, requestID)
	}

	// Generic error fallback - return a internal error response
	return &ErrorResponse{
		HTTPMethod:                   r.Method,
		RequestURI:                   r.RequestURI,
		StatusCode:                   http.StatusInternalServerError,
		StatusCodeText:               http.StatusText(http.StatusInternalServerError),
		StatusCodeMessage:            "Internal Error",
		ProviderCorrelationReference: requestID,
		ErrorDateTime:                time.Now().UTC().Format(time.RFC3339),
		Errors: []DetailedError{
			{
				ErrorCode:        ErrCodeInternalError,
				ErrorCodeText:    "Internal Error",
				ErrorCodeMessage: "An internal error occurred",
			},
		},
	}
}

// errorResponseFromCrypto maps crypto.Error to API error responses
func errorResponseFromCrypto(err *crypto.CryptoError, r *http.Request, requestID string) *ErrorResponse {
	var statusCode int
	var errorCode ErrorCode
	var errorCodeText string

	switch err.Code() {
	case crypto.ErrCodeInvalidSignature:
		statusCode = http.StatusBadRequest
		errorCode = ErrCodeBadSignature
		errorCodeText = "Bad Signature"
	case crypto.ErrCodeCertificate:
		statusCode = http.StatusBadRequest
		errorCode = ErrCodeBadCertificate
		errorCodeText = "Bad Certificate"
	case crypto.ErrCodeInvalidChecksum:
		statusCode = http.StatusBadRequest
		errorCode = ErrCodeBadChecksum
		errorCodeText = "Bad Checksum"
	case crypto.ErrCodeValidation:
		statusCode = http.StatusBadRequest
		errorCode = ErrCodeInvalidEnvelope
		errorCodeText = "Invalid Envelope"
	case crypto.ErrCodeKeyManagement:
		statusCode = http.StatusBadRequest
		errorCode = ErrCodeKeyError
		errorCodeText = "Error retrieving public key"
	default:
		statusCode = http.StatusInternalServerError
		errorCode = ErrCodeInternalError
		errorCodeText = "Internal Error"
	}

	return &ErrorResponse{
		HTTPMethod:                   r.Method,
		RequestURI:                   r.RequestURI,
		StatusCode:                   statusCode,
		StatusCodeText:               http.StatusText(statusCode),
		StatusCodeMessage:            errorCodeText,
		ProviderCorrelationReference: requestID,
		ErrorDateTime:                time.Now().UTC().Format(time.RFC3339),
		Errors: []DetailedError{
			{
				ErrorCode:        errorCode,
				ErrorCodeText:    errorCodeText,
				ErrorCodeMessage: err.Error(),
			},
		},
	}
}

// errorResponseFromEbl maps ebl.Error to DCSA error response
func errorResponseFromEbl(err *ebl.EblError, r *http.Request, requestID string) *ErrorResponse {
	var statusCode int
	var errorCode ErrorCode
	var errorCodeText string

	switch err.Code() {
	case ebl.ErrCodeSignature:
		statusCode = http.StatusBadRequest
		errorCode = ErrCodeBadSignature
		errorCodeText = "Bad Signature"
	case ebl.ErrCodeEnvelope:
		statusCode = http.StatusBadRequest
		errorCode = ErrCodeInvalidEnvelope
		errorCodeText = "Invalid Envelope"
	default:
		statusCode = http.StatusInternalServerError
		errorCode = ErrCodeInternalError
		errorCodeText = "Internal Error"
	}

	return &ErrorResponse{
		HTTPMethod:                   r.Method,
		RequestURI:                   r.RequestURI,
		StatusCode:                   statusCode,
		StatusCodeText:               http.StatusText(statusCode),
		StatusCodeMessage:            errorCodeText,
		ProviderCorrelationReference: requestID,
		ErrorDateTime:                time.Now().UTC().Format(time.RFC3339),
		Errors: []DetailedError{
			{
				ErrorCode:        errorCode,
				ErrorCodeText:    errorCodeText,
				ErrorCodeMessage: err.Error(),
			},
		},
	}
}

// NewErrorResponse creates a new error response.
func NewErrorResponse(r *http.Request, statusCode int, errorCode ErrorCode, errorCodeText string, errorCodeMessage string, property string, jsonPath string) *ErrorResponse {
	requestID := middleware.GetReqID(r.Context())

	return &ErrorResponse{
		HTTPMethod:                   r.Method,
		RequestURI:                   r.RequestURI,
		StatusCode:                   statusCode,
		StatusCodeText:               http.StatusText(statusCode),
		StatusCodeMessage:            errorCodeText,
		ProviderCorrelationReference: requestID,
		ErrorDateTime:                time.Now().UTC().Format(time.RFC3339),
		Errors: []DetailedError{
			{
				ErrorCode:        errorCode,
				Property:         property,
				JSONPath:         jsonPath,
				ErrorCodeText:    errorCodeText,
				ErrorCodeMessage: errorCodeMessage,
			},
		},
	}
}
