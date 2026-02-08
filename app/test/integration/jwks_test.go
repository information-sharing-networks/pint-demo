//go:build integration

package integration

import (
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestJWKSEndpoint(t *testing.T) {

	testEnv := startInProcessServer(t, "EBL1")
	testDomain := "ed25519-eblplatform.example.com"

	// the jwk returned by the endpoint should match with the manually configured key for the testDomain
	testKeyPath := fmt.Sprintf("../../internal/crypto/testdata/keys/%s.public.jwk", testDomain)

	// Note: this will need updating when the app is updated to support key rotation (currently only one key is supported)
	// get the first (only) key from the test key file
	expectedKeySetBytes, err := os.ReadFile(testKeyPath)
	if err != nil {
		t.Fatalf("failed to read test public key file: %v", err)
	}

	expectedKeySet, err := jwk.Parse([]byte(expectedKeySetBytes))
	if err != nil {
		t.Fatalf("failed to parse test public key file: %v", err)
	}

	if expectedKeySet.Len() != 1 {
		t.Fatalf("expected 1 key in test public key file, got %d", expectedKeySet.Len())
	}

	expectedKey, ok := expectedKeySet.Key(0)
	if !ok {
		t.Fatalf("failed to get key from public key file: %v", err)
	}
	expectedKeyID, ok := expectedKey.KeyID()
	if !ok || expectedKeyID == "" {
		t.Fatalf("failed to get key id from public key file: %v", err)
	}

	defer testEnv.shutdown()

	jwksURL := testEnv.baseURL + "/.well-known/jwks.json"

	resp, err := http.Get(jwksURL)
	if err != nil {
		t.Fatalf("failed to fetch JWKS endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}

	// Read and parse as JWKS
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	set, err := jwk.Parse(body)
	if err != nil {
		t.Fatalf("failed to parse JWKS: %v", err)
	}

	// Verify we have at least one key
	if set.Len() == 0 {
		t.Fatal("JWKS contains no keys")
	}

	// validate each key
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			t.Errorf("failed to get key at index %d", i)
			continue
		}

		// Check required fields
		keyID, ok := key.KeyID()
		if !ok || keyID == "" {
			t.Errorf("key %d: kid is empty", i)
		}

		// get the expected key id from the public key file

		if keyID != expectedKeyID {
			t.Errorf("key %d: expected key id for %s to be %v, got %s", i, testDomain, expectedKeyID, keyID)
		}

		if keyUsage, ok := key.KeyUsage(); !ok || keyUsage == "" {
			t.Errorf("key %d: use is empty", i)
		}

		if alg, ok := key.Algorithm(); !ok || alg.String() == "" {
			t.Errorf("key %d: alg is empty", i)
		}

		// verify the key is a valid RSA or Ed25519 public key
		var rawKey any
		if err := jwk.Export(key, &rawKey); err != nil {
			t.Errorf("key %d: failed to convert to raw key: %v", i, err)
			continue
		}

		if _, ok := rawKey.(*rsa.PublicKey); !ok {
			if _, ok := rawKey.(ed25519.PublicKey); !ok {
				t.Errorf("key %d: not a valid RSA or Ed25519 public key", i)
			}
		}
	}
}
