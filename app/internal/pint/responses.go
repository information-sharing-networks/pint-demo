package pint

// responses.go provides helper functions for sending HTTP responses from the PINT API handlers.

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/information-sharing-networks/pint-demo/app/internal/logger"
)

// RespondWithError sends a DCSA-formatted error response as a JSON payload.
//
// Use this function when a request faied because it was malformed or because of a server-side error
// prevents signing the response.
//
// It logs the full error details server-side and sends a sanitized response to the client
func RespondWithError(w http.ResponseWriter, r *http.Request, err error) {
	// Map the error to DCSA format
	errorResponse := MapErrorToResponse(err, r)

	// Log the full error details server-side
	reqLogger := logger.ContextRequestLogger(r.Context())
	reqLogger.Warn("Request failed",
		slog.String("error", err.Error()),
		slog.Int("status_code", errorResponse.StatusCode),
		slog.String("error_code_text", errorResponse.StatusCodeMessage),
		slog.String("request_id", errorResponse.ProviderCorrelationReference),
	)

	// Send the DCSA error response
	RespondWithPayload(w, errorResponse.StatusCode, errorResponse)
}

// RespondWithPayload sends a JSON response with the given status code
//
// Use this function when returning a standard response to the client, including
// expected PINT errors (e.g. BSIG, BENV, etc.)
//
// If returning information about an unexpected error (e.g a request failed because of
// an internal server error), use RespondWithError which will create an unsigned error response.
func RespondWithPayload(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if payload != nil {
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			// If encoding fails, log it but don't try to send another response
			// (headers are already written)
			// #nosec G706 -- False positive: error is escaped (slog) and not from user input
			slog.Error("Failed to encode JSON response",
				slog.String("error", err.Error()),
			)
		}
	}
}

// RespondWithStatusCodeOnly sends a response with only a status code (no body)
func RespondWithStatusCodeOnly(w http.ResponseWriter, statusCode int) {
	w.WriteHeader(statusCode)
}

// RespondWithSignedRejection sends a signed DCSA rejection response and logs the rejection details.
//
// Use this function when returning a signed rejection response (BSIG, BENV, MDOC, INCD, DISE)
// to ensure proper logging of the rejection for monitoring and debugging.
func RespondWithSignedRejection(w http.ResponseWriter, r *http.Request, statusCode int, signedResponse *SignedEnvelopeTransferFinishedResponse, responseCode ResponseCode, reason string) {
	reqLogger := logger.ContextRequestLogger(r.Context())

	// Determine log level based on response code
	// BSIG/BENV are warnings (expected validation failures)
	// MDOC/INCD are info (temporary states that may resolve)
	logLevel := slog.LevelWarn
	if responseCode == ResponseCodeMDOC || responseCode == ResponseCodeINCD {
		logLevel = slog.LevelInfo
	}

	reqLogger.Log(r.Context(), logLevel, "Signed rejection response",
		slog.String("response_code", string(responseCode)),
		slog.String("reason", reason),
		slog.Int("status_code", statusCode),
		slog.String("error_code", string(responseCode)),
	)

	RespondWithPayload(w, statusCode, signedResponse)
}
