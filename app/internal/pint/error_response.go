package pint

// error_response.go implements the DCSA standard error response format for the PINT API
// it includes functions to map lower level errors to the DCSA error response format (returned to the client

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/information-sharing-networks/pint-demo/app/internal/ebl"
	"github.com/information-sharing-networks/pint-demo/app/internal/logger"
)

// ErrorResponse represents the DCSA error response format
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
	// error code used on the platform: 7000-7999 for technical errors, 8000-8999 for functional errors
	ErrorCode        ErrorCode `json:"errorCode"`
	Property         string    `json:"property,omitempty"`
	Value            string    `json:"value,omitempty"`
	JSONPath         string    `json:"jsonPath,omitempty"`
	ErrorCodeText    string    `json:"errorCodeText"`
	ErrorCodeMessage string    `json:"errorCodeMessage"`
}

// MapErrorToResponse maps pint.Error, ebl.Error, crypto.Error, or generic errors to a DCSA error response.
//
// The error code text is sanitized for the response, but the full error message is logged server-side.
// The mapping also establishes the appropriate HTTP status code based on the error type.
//
// Call this function to set up the error response before sending it to the client (using responses.RespondWithError).
func MapErrorToResponse(err error, r *http.Request) *ErrorResponse {
	requestID := middleware.GetReqID(r.Context())

	// Try to extract the most specific error type first (pint.Error)
	var pintErr *PintError
	if errors.As(err, &pintErr) {
		return errorResponseFromPint(pintErr, r, requestID)
	}

	// Then try crypto.Error
	var cryptoErr *crypto.CryptoError
	if errors.As(err, &cryptoErr) {
		return errorResponseFromCrypto(cryptoErr, r, requestID)
	}

	// Then try ebl.Error (non-crypto ebl package errors)
	var eblErr *ebl.EblError
	if errors.As(err, &eblErr) {
		return errorResponseFromEbl(eblErr, r, requestID)
	}

	// fallback - this is not expectedi - if it does, return an internal error response and log the unmapped error
	reqLogger := logger.ContextRequestLogger(r.Context())
	reqLogger.Error("BUG: Unmapped error type in MapErrorToResponse",
		slog.String("error_type", fmt.Sprintf("%T", err)),
		slog.String("error", err.Error()),
		slog.String("request_id", requestID),
	)
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

// errorResponseFromPint maps pint.Error to API error responses
// the error code text is sanitized for the response, but the full error message is logged server-side
func errorResponseFromPint(err *PintError, r *http.Request, requestID string) *ErrorResponse {
	var statusCode int
	var errorCodeText string

	// Map error code to HTTP status and text
	switch err.Code() {
	case ErrCodeBadCertificate:
		statusCode = http.StatusBadRequest
		errorCodeText = "Bad certificate"
	case ErrCodeBadChecksum:
		statusCode = http.StatusBadRequest
		errorCodeText = "Bad checksum"
	case ErrCodeBadSignature:
		statusCode = http.StatusBadRequest
		errorCodeText = "Bad signature"
	case ErrCodeInsufficientTrust:
		statusCode = http.StatusBadRequest
		errorCodeText = "Insufficient trust level"
	case ErrCodeInvalidEnvelope:
		statusCode = http.StatusBadRequest
		errorCodeText = "Invalid envelope"
	case ErrCodeKeyError:
		statusCode = http.StatusBadRequest
		errorCodeText = "Error retrieving public key"
	case ErrCodeMalformedRequest:
		statusCode = http.StatusBadRequest
		errorCodeText = "Malformed request"
	case ErrCodeNotFound:
		statusCode = http.StatusNotFound
		errorCodeText = "Not found"
	case ErrCodeRateLimitExceeded:
		statusCode = http.StatusTooManyRequests
		errorCodeText = "Rate limit exceeded"
	case ErrCodeRequestTooLarge:
		statusCode = http.StatusRequestEntityTooLarge
		errorCodeText = "Request too large"
	case ErrCodeUnknownParty:
		statusCode = http.StatusNotFound
		errorCodeText = "Unknown party"
	default:
		statusCode = http.StatusInternalServerError
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
				ErrorCode:        err.Code(),
				ErrorCodeText:    errorCodeText,
				ErrorCodeMessage: err.Error(),
			},
		},
	}
}

// errorResponseFromCrypto maps crypto.Error to API error responses
// the error code text is sanitized for the response, but the full error message is logged server-side
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
// the error code text is sanitized for the response, but the full error message is logged server-side
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
