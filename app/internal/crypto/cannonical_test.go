package crypto

import "testing"

// test that cannonical rejects invalid json

func TestCanonicalizeJSON(t *testing.T) {
	// invalid json
	jsonData := []byte(`{"test": "value"`)
	_, err := CanonicalizeJSON(jsonData)
	if err == nil {
		t.Fatalf("CanonicalizeJSON() expected error, got nil")
	}
	t.Logf("CanonicalizeJSON() correctly rejected invalid JSON: %v", err)
}
