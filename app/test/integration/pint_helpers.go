//go:build integration

package integration

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/information-sharing-networks/pint-demo/app/internal/pint"
)

// decodeSignedFinishedResponse decodes a SignedEnvelopeTransferFinishedResponse
// and returns the payload (assumes the signature is valid).
// the SigneEnvelopeTransferFinishedResponse is returned by the start envelope API when it processes a  DUPE, RECE, BSIG, BENV responses
func decodeSignedFinishedResponse(t *testing.T, SignedResponse pint.SignedEnvelopeTransferFinishedResponse) pint.EnvelopeTransferFinishedResponse {
	t.Helper()

	// JWS format is header.payload.signature
	parts := strings.Split(SignedResponse.SignedContent, ".")
	if len(parts) != 3 {
		t.Fatalf("Invalid JWS format: expected 3 parts, got %d", len(parts))
	}

	// Decode the base64url-encoded payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode JWS payload: %v", err)
	}

	// Unmarshal the JSON payload
	var payload pint.EnvelopeTransferFinishedResponse
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	return payload
}
