package commonhandlers

import (
	"encoding/json"
	"net/http"
)

// HandleVersion godoc
//
//	@Summary		Get version information
//	@Description	Returns the version and build information for the service
//	@Tags			Common
//	@Produce		json
//	@Success		200	{object}	VersionResponse	"Version information"
//	@Router			/version [get]
func HandleVersion(version, buildTime string) http.HandlerFunc {
	// Pre-create the response to avoid allocating on every request
	response := VersionResponse{
		Version:   version,
		BuildTime: buildTime,
		Service:   "pint-server",
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Failed to encode version", http.StatusInternalServerError)
			return
		}
	}
}

type VersionResponse struct {
	Version   string `json:"version" example:"1.0.0"`
	BuildTime string `json:"build_time" example:"2024-01-28T10:00:00Z"`
	Service   string `json:"service" example:"pint-server"`
}
