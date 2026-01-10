package crypto

import (
	"testing"
)

func TestHash(t *testing.T) {

	// check that empty input returns an error
	input := []byte("")
	_, err := Hash(input)
	if err == nil {
		t.Fatalf("Hash() expected error, got nil")
	}

	// check the function retuns a dcsa-compliant hash (lowercase hex, 64 characters)
	input = []byte("hello world")
	result, err := Hash(input)
	if err != nil {
		t.Fatalf("Hash() returned error: %v", err)
	}

	// Check that result is 64 hex characters (SHA-256)
	if len(result) != 64 {
		t.Errorf("Hash() returned %d characters, expected 64", len(result))
	}

	// Check that result is lowercase hex
	for _, c := range result {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Hash() returned non-hex character: %c", c)
		}
	}

}

func TestHashFromBase64(t *testing.T) {
	// check the function retuns a dcsa-compliant hash (lowercase hex, 64 characters)
	// check that invalid base64 returns an error
	// check that maxSize is enforced

	tests := []struct {
		name     string
		input    string
		maxSize  int64
		expected string
		wantErr  bool
	}{
		{
			name:    "empty string",
			input:   "",
			maxSize: 1000,
			wantErr: true,
		},
		{
			name:    "valid base64",
			input:   "aGVsbG8gd29ybGQ=",
			maxSize: 1000,
			wantErr: false,
		},
		{
			name:     "invalid base64",
			input:    "!invalid base64!",
			maxSize:  1000,
			expected: "",
			wantErr:  true,
		},
		{
			name:     "oversized base64",
			input:    "aGVsbG8gd29ybGQ=",
			maxSize:  1,
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := HashFromBase64(tt.input, tt.maxSize)
			if tt.wantErr {
				if err == nil {
					t.Errorf("HashFromBase64() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("HashFromBase64() returned error: %v", err)
			}

			// Check that result is 64 hex characters (SHA-256)
			if len(result) != 64 {
				t.Errorf("HashFromBase64() returned %d characters, expected 64", len(result))
			}

			// Check that result is lowercase hex
			for _, c := range result {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("HashFromBase64() returned non-hex character: %c", c)
				}
			}

		})
	}

}
