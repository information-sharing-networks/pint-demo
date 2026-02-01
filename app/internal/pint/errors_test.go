package pint

import "testing"

// sanity check that the error codes are in the correct range

func TestErrorCodes(t *testing.T) {
	tests := []struct {
		name     string
		errCode  ErrorCode
		wantCode int
	}{
		{"bad_signature", ErrCodeBadSignature, 7001},
		{"bad_certificate", ErrCodeBadCertificate, 7002},
		{"bad_checksum", ErrCodeBadChecksum, 7003},
		{"invalid_envelope", ErrCodeInvalidEnvelope, 7004},
		{"internal_error", ErrCodeInternalError, 7005},
		{"malformed_json", ErrCodeMalformedRequest, 7006},
		{"key_error", ErrCodeKeyError, 7007},
		{"registry_error", ErrCodeRegistryError, 7008},
		{"unknown_party", ErrCodeUnknownParty, 8001},
		{"insufficient_trust", ErrCodeInsufficientTrust, 8002},
	}
	for _, tt := range tests {
		if int(tt.errCode) != tt.wantCode {
			t.Errorf("%s: got %d, want %d", tt.name, tt.errCode, tt.wantCode)
		}
	}
}
