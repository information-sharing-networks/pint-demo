package pint

import (
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// TODO: end2end test with jwk endpoint
func TestKeyManager_LoadRegistry(t *testing.T) {
	ctx := context.Background()
	url := "../crypto/testdata/platform-registry/eblsolutionproviders.csv"
	config := NewKeymanagerConfig(url, "", 30*time.Second, true, 15*time.Minute, 12*time.Hour)

	// Create a test logger that discards output
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	km, err := NewKeyManager(ctx, config, logger)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	expectedProviderCount := 4 // EBL1, CAR1, EBL2, CAR2
	if len(km.eblSolutionProviders) != expectedProviderCount {
		t.Fatalf("expected %d eBL solution providers, got %d", expectedProviderCount, len(km.eblSolutionProviders))
	}

	// Check for expected providers (based on the CSV file)
	expectedProviders := map[string]struct {
		site         string
		jwksEndpoint string
		manualKeyID  string
	}{
		"EBL1": {"https://ed25519-eblplatform.example.com/", "", "ea8904dc74e9395a"},
		"CAR1": {"https://ed25519-carrier.example.com/", "", "90c692d328071e01"},
		"EBL2": {"https://rsa-eblplatform.example.com/", "", "7f6dc8fe0df74997"},
		"CAR2": {"https://rsa-carrier.example.com/", "https://rsa-carrier.example.com/.well-known/jwks.json", ""},
	}

	for code, expected := range expectedProviders {
		provider, exists := km.eblSolutionProviders[code]
		if !exists {
			t.Errorf("expected provider code %s not found in registry", code)
			continue
		}

		// Verify provider has required fields
		if provider.Code != code {
			t.Errorf("provider %s has wrong Code: got %s, want %s", code, provider.Code, code)
		}
		if provider.Site != expected.site {
			t.Errorf("provider %s has wrong Site: got %s, want %s", code, provider.Site, expected.site)
		}
		if provider.JWKSEndpoint != expected.jwksEndpoint {
			t.Errorf("provider %s has wrong JWKSEndpoint: got %s, want %s", code, provider.JWKSEndpoint, expected.jwksEndpoint)
		}
		if provider.ManualKeyID != expected.manualKeyID {
			t.Errorf("provider %s has wrong ManualKeyID: got %s, want %s", code, provider.ManualKeyID, expected.manualKeyID)
		}

	}
}

func TestKeyManager_LoadManualKeys(t *testing.T) {
	tempDir := t.TempDir()

	jwkName := "ed25519-eblplatform.example.com.public.jwk"

	publicKeyPath := "../crypto/testdata/keys/" + jwkName

	keyID := "ea8904dc74e9395a"

	// Copy the public key to the temp dir (don't move it!)
	publicKeyDest := tempDir + "/" + jwkName
	src, err := os.Open(publicKeyPath)
	if err != nil {
		t.Fatalf("failed to open source key file: %v", err)
	}
	defer src.Close()

	dst, err := os.Create(publicKeyDest)
	if err != nil {
		t.Fatalf("failed to create destination key file: %v", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		t.Fatalf("failed to copy public key to temp dir: %v", err)
	}

	// Create a KeyManager with that will load the public key we just saved
	// Testing keys without certificates
	ctx := context.Background()
	RegistryPath := "../crypto/testdata/platform-registry/eblsolutionproviders.csv"
	config := NewKeymanagerConfig(RegistryPath, tempDir, 30*time.Second, true, 15*time.Minute, 12*time.Hour)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	km, err := NewKeyManager(ctx, config, logger)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	// Verify public key was loaded by getting the key by its KID
	key, err := km.GetKey(ctx, keyID)
	if err != nil {
		t.Fatalf("failed to get key: %v", err)
	}
	if key == nil {
		t.Fatalf("expected key to be loaded, got nil")
	}

	// Verify key metadata
	if key.Provider.Code != "EBL1" {
		t.Errorf("expected provider code EBL1, got %s", key.Provider.Code)
	}

	// Verify key type
	var raw any
	if err := jwk.Export(key.Key, &raw); err != nil {
		t.Fatalf("failed to export key: %v", err)
	}
	if _, ok := raw.(ed25519.PublicKey); !ok {
		t.Errorf("expected ed25519 public key, got %T", raw)
	}

}

func TestKeyManager_LoadManualKeys_RejectsMultipleKeys(t *testing.T) {
	tempDir := t.TempDir()

	// Create a temporary registry CSV
	registryPath := tempDir + "/registry.csv"
	registryContent := `Code,Site,jwks_endpoint,manual_key_id
TEST,https://test.example.com/,,key-old-2024
`
	if err := os.WriteFile(registryPath, []byte(registryContent), 0644); err != nil {
		t.Fatalf("failed to create registry file: %v", err)
	}

	// Create a JWKS file with multiple keys (should be rejected)
	multiKeyFile := tempDir + "/multi-key.jwks.json"
	multiKeyContent := `{
  "keys": [
    {
      "alg": "EdDSA",
      "crv": "Ed25519",
      "kid": "key-old-2024",
      "kty": "OKP",
      "use": "sig",
      "x": "BPYmiGbFLpPaNvNr_kXcDjRy65JWnfpixGxpuEISFrs"
    },
    {
      "alg": "EdDSA",
      "crv": "Ed25519",
      "kid": "key-new-2025",
      "kty": "OKP",
      "use": "sig",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
  ]
}`
	if err := os.WriteFile(multiKeyFile, []byte(multiKeyContent), 0644); err != nil {
		t.Fatalf("failed to create multi-key file: %v", err)
	}

	// Create a KeyManager - it should reject the file with multiple keys
	ctx := context.Background()
	RegistryPath := registryPath
	config := NewKeymanagerConfig(RegistryPath, tempDir, 30*time.Second, true, 15*time.Minute, 12*time.Hour)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	km, err := NewKeyManager(ctx, config, logger)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	// Verify that NO keys were loaded (file was rejected)
	_, err = km.GetKey(ctx, "key-old-2024")
	if err == nil {
		t.Errorf("expected error when getting key from rejected multi-key file, got nil")
	}

	_, err = km.GetKey(ctx, "key-new-2025")
	if err == nil {
		t.Errorf("expected error when getting key from rejected multi-key file, got nil")
	}
}
