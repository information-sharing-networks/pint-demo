//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"io"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestJWKSEndpoint(t *testing.T) {

	// note the the JWKS returned in this test is configured by the env vars set in startInProcessServer
	// currently the jwks is for ed25519-eblplatform.example.com.private.jwk which has the public key thumbprint (key id) ea8904dc74e9395a

	ctx := context.Background()
	testDB := setupTestDatabase(t, ctx)
	testEnv := setupTestEnvironment(testDB)
	testDatabaseURL := getTestDatabaseURL()
	baseURL, stopServer := startInProcessServer(t, ctx, testEnv.dbConn, testDatabaseURL)

	defer stopServer()

	jwksURL := baseURL + "/.well-known/jwks.json"

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

		if keyID != "ea8904dc74e9395a" { // from ed25519-eblplatform.example.com.public.jwk
			t.Errorf("key %d: expected key id for ed25519-eblplatform.example.com to be ea8904dc74e9395a, got %s", i, keyID)
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
