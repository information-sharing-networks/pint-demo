package pint

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/information-sharing-networks/pint-demo/app/internal/logger"
)

// RespondWithError sends a DCSA-formatted error response
// It logs the full error details server-side and sends a sanitized response to the client
func RespondWithError(w http.ResponseWriter, r *http.Request, err error) {
	// Map the error to DCSA format
	errorResponse := MapErrorToResponse(err, r)

	// Log the full error details server-side
	reqLogger := logger.ContextRequestLogger(r.Context())
	reqLogger.Error("Request failed",
		slog.String("error", err.Error()),
		slog.Int("status_code", errorResponse.StatusCode),
		slog.String("error_code_text", errorResponse.StatusCodeMessage),
		slog.String("request_id", errorResponse.ProviderCorrelationReference),
	)

	// Send the DCSA error response
	RespondWithJSON(w, errorResponse.StatusCode, errorResponse)
}

// RespondWithJSON sends a JSON response with the given status code
func RespondWithJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if payload != nil {
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			// If encoding fails, log it but don't try to send another response
			// (headers are already written)
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
