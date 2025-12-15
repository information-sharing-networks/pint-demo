package server

import (
	"log/slog"
	"net/http"
)

// handleJWKS serves the JWK Set endpoint at /.well-known/jwks.json
// TODO: Implement JWK Set endpoint handler
// - Load platform's public key(s) from configuration or key store
// - Convert to JWK format using crypto.PublicKeyToJWK
// - Create JWK Set using crypto.CreateJWKSet
// - Marshal to JSON using crypto.MarshalJWKSet
// - Set Content-Type: application/json
// - Set Cache-Control header (e.g., "public, max-age=3600")
// - Write JSON response
//
// This endpoint allows other platforms to discover our public keys
// Reference: RFC 8414 (OAuth 2.0 Authorization Server Metadata)
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement JWK Set endpoint
	// Example response:
	// {
	//   "keys": [
	//     {
	//       "kty": "RSA",
	//       "use": "sig",
	//       "kid": "platform-a-key-1",
	//       "alg": "RS256",
	//       "n": "...",
	//       "e": "AQAB"
	//     }
	//   ]
	// }

	s.logger.Info("JWK Set endpoint called",
		slog.String("remote_addr", r.RemoteAddr))

	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

