package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// HandleJWKS godoc
//
//	@Summary		Get JWK set
//	@Description	Returns the JWK set for the platform.
//	@Description
//	@Description	Use this endpoint to retrieve the public key needed to verify signatures from this platform.
//	@Description
//	@Description	The JWK set in the response conforms to the [JWK specification](https://datatracker.ietf.org/doc/html/rfc7517).
//	@Description
//	@Description	Note: this service supports Ed25519 and RSA public keys so you should expect to see either of these key types in the returned JWK set.
//	@Tags			Common
//
//	@Success		200	{object}	JWKSResponse	"JWK set"
//
//	@Router			/.well-known/jwks.json [get]
func HandleJWKS(jwkSet jwk.Set) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwkSet); err != nil {
			http.Error(w, "Failed to encode JWK set", http.StatusInternalServerError)
			return
		}
	}
}

// JWKSResponse is used for swaggo documentation as swaggo doesn't support the jwk.Set interface type.
type JWKSResponse struct {
	Keys []map[string]any `json:"keys"`
}
