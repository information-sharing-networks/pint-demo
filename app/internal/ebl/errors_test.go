package ebl

import (
	"errors"
	"testing"
)

// check to ensure error code handling has not been broken
func TestEblError_Code(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode ErrorCode
	}{
		{"signature", NewSignatureError("test"), ErrCodeSignature},
		{"envelope", NewEnvelopeError("test"), ErrCodeEnvelope},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var eblErr *EblError
			if !errors.As(tt.err, &eblErr) {
				t.Fatal("error is not an EblError")
			}
			if eblErr.Code() != tt.wantCode {
				t.Errorf("Code() = %q, want %q", eblErr.Code(), tt.wantCode)
			}
		})
	}
}
