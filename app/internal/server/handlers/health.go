package handlers

import (
	"net/http"

	"github.com/information-sharing-networks/pint-demo/app/internal/database"
)

// HandleHealth godoc
//
//	@Summary		Health (liveness) Check
//	@Description	Check if the HTTP service is alive and responding.
//	@Tags			Common
//	@Produce		plain
//
//	@Success		200	{string}	string	"OK"
//
//	@Router			/health/live [get]
func HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// HandleReadiness godoc
//
//	@Summary		Readiness Check
//	@Description	Checks if the service is ready to accept traffic (includes database connectivity)
//	@Tags			Common
//	@Produce		json
//	@Success		200	{object}	map[string]string	"status ready"
//	@Failure		503	{object}	map[string]string	"status not ready"
//	@Router			/ready [get]
func HandleReadiness(queries *database.Queries) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Check database connectivity
		_, err := queries.IsDatabaseRunning(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"not ready","reason":"database unavailable"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	}
}
