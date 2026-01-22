package crypto

import (
	"errors"
	"testing"
)

// check to ensure error code handling has not been broken
func TestCryptoError_Code(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode ErrorCode
	}{
		{"validation", NewValidationError("test"), ErrCodeValidation},
		{"checksum", NewChecksumError("test"), ErrCodeInvalidChecksum},
		{"signature", NewSignatureError("test"), ErrCodeInvalidSignature},
		{"certificate", NewCertificateError("test"), ErrCodeCertificate},
		{"key_management", NewKeyManagementError("test"), ErrCodeKeyManagement},
		{"internal", NewInternalError("test"), ErrCodeInternal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cryptoErr *CryptoError
			if !errors.As(tt.err, &cryptoErr) {
				t.Fatal("error is not a CryptoError")
			}
			if cryptoErr.Code() != tt.wantCode {
				t.Errorf("Code() = %q, want %q", cryptoErr.Code(), tt.wantCode)
			}
		})
	}
}
