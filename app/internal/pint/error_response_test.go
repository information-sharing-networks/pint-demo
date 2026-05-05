package pint

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/information-sharing-networks/pint-demo/app/internal/ebl"
)

// TestErrorResponseDoesNotLeakDetails covers that ErrorCodeMessage carries only
// the caller-supplied message for 4xx errors and "Internal Error" for 5xx
func TestErrorResponseDoesNotLeakDetails(t *testing.T) {
	detailedError := errors.New("detailed error (hide from client)")

	tests := []struct {
		name        string
		err         error
		wantMessage string
	}{
		{"pint_4xx", WrapMalformedRequestError(detailedError, "failed to decode envelope JSON"), "failed to decode envelope JSON"},
		{"pint_5xx", WrapInternalError(detailedError, "failed to retrieve envelope"), "Internal Error"},
		{"crypto_4xx", crypto.WrapValidationError(detailedError, "failed to parse JWS"), "failed to parse JWS"},
		{"ebl_4xx", ebl.WrapEnvelopeError(detailedError, "actor: eBLPlatform is required"), "actor: eBLPlatform is required"},
	}

	r := httptest.NewRequest(http.MethodPost, "/test", nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := errorResponseFromError(tt.err, r).Errors[0].ErrorCodeMessage
			if got != tt.wantMessage {
				t.Errorf("ErrorCodeMessage: got %q, want %q", got, tt.wantMessage)
			}
			if strings.Contains(got, detailedError.Error()) {
				t.Errorf("ErrorCodeMessage leaked wrapped detail: %q", got)
			}
		})
	}
}
