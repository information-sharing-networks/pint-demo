package pint

// responses.go provides helper functions for sending HTTP responses from the PINT API handlers.

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/information-sharing-networks/pint-demo/app/internal/logger"
)

// RespondWithErrorResponse sends a DCSA-formatted error response as a JSON payload.
//
// Use this function when a request faied because it was malformed or because of a server-side error
// prevents signing the response.
//
// It logs the full error details server-side and sends a sanitized response to the client
func RespondWithErrorResponse(w http.ResponseWriter, r *http.Request, err error) {
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

	RespondWithJSONPayload(w, errorResponse.StatusCode, errorResponse)
}

// RespondWithJSONPayload sends a JSON response with the given status code
//
// Use this function when returning a standard response to the client, including
// expected PINT errors (e.g. BSIG, BENV, etc.)
//
// If returning information about an unexpected error (e.g a request failed because of
// an internal server error), use RespondWithError which will create an unsigned error response.
func RespondWithJSONPayload(w http.ResponseWriter, statusCode int, payload any) {
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

// RespondWithSignedContent sends a signed response (JWS token) as the raw response body.
//
// The JWS token is sent as a json string in the response body.
// This is used for PINT signed responses (RECE, DUPE, BSIG, BENV, MDOC, INCD, DISE).
func RespondWithSignedContent(w http.ResponseWriter, statusCode int, signedResponse SignedEnvelopeTransferFinishedResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	// json marshal the signed response so it quoted as a json string in the response body
	jsonBytes, err := json.Marshal(signedResponse)
	if err != nil {
		slog.Error("Failed to marshal signed response",
			slog.String("error", err.Error()),
		)
		return
	}
	if _, err := w.Write(jsonBytes); err != nil {
		// If writing fails, log it but don't try to send another response
		// (headers are already written)
		slog.Error("Failed to write signed response",
			slog.String("error", err.Error()),
		)
	}
}
