package crypto

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// TODO: end2end test with jwk endpoint
func TestKeyManager_LoadRegistry(t *testing.T) {
	ctx := context.Background()
	url, _ := url.Parse("testdata/platform-registry/eblsolutionproviders.csv")
	config := NewConfig(url, "", TrustLevelDV, 30*time.Second, true)

	// Create a test logger that discards output
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	km, err := NewKeyManager(ctx, config, logger)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	// Verify that providers were loaded
	if len(km.eblSolutionProviders) != 4 {
		t.Fatalf("expected 4 eBL solution providers, got %d", len(km.eblSolutionProviders))
	}

	// Check for expected providers (based on the CSV file)
	expectedDomains := []string{
		"wavebl.com",
		"cargox.io",
		"web.edoxonline.com",
	}

	for _, domain := range expectedDomains {
		provider, exists := km.eblSolutionProviders[domain]
		if !exists {
			t.Errorf("expected domain %s not found in registry", domain)
			continue
		}

		// Verify provider has required fields
		if provider.Name == "" {
			t.Errorf("provider %s has empty Name", domain)
		}
		if provider.Code == "" {
			t.Errorf("provider %s has empty Code", domain)
		}
		if provider.URL == nil {
			t.Errorf("provider %s has nil URL", domain)
		}

		t.Logf("%s: %s (%s)", domain, provider.Name, provider.Code)
	}
}

func TestKeyManager_FetchRegistryData(t *testing.T) {
	tests := []struct {
		name    string
		urlStr  string
		wantErr bool
	}{
		{
			name:    "remote file",
			urlStr:  "https://github.com/dcsaorg/DCSA-OpenAPI/raw/master/reference-data/eblsolutionproviders-v3.0.0.csv",
			wantErr: false,
		},
		{
			name:    "local file",
			urlStr:  "testdata/platform-registry/eblsolutionproviders.csv",
			wantErr: false,
		},
		{
			name:    "file not found",
			urlStr:  "testdata/nonexistent.csv",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			url, _ := url.Parse(tt.urlStr)

			config := NewConfig(
				url,
				"nodir",
				TrustLevelDV,
				10*time.Second,
				true,
			)
			km := &KeyManager{
				config:               config,
				eblSolutionProviders: make(map[string]*eblSolutionProvider),
				httpClient: &http.Client{
					Timeout: config.HTTPTimeout,
				},
			}

			data, err := km.fetchRegistryData(ctx)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(data) == 0 {
				t.Error("expected data, got empty byte slice")
			}

			t.Logf("fetched %d bytes", len(data))
		})
	}
}

func TestKeyManager_LoadManualKeys(t *testing.T) {
	tempDir := t.TempDir()

	// Generate keys
	hostname := "eblplatform.example.com"

	privateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)

	keyID, err := GenerateKeyIDFromEd25519Key(publicKey)
	if err != nil {
		t.Fatalf("failed to generate key ID: %v", err)
	}

	// Save public key file
	publicKeyPath := filepath.Join(tempDir, hostname+".public.jwk")
	if err := SaveEd25519PublicKeyToFile(publicKey, keyID, publicKeyPath); err != nil {
		t.Fatalf("failed to save public key: %v", err)
	}

	// Save private key file (should not be loaded)
	privateKeyPath := filepath.Join(tempDir, hostname+".private.jwk")
	if err := SaveEd25519PrivateKeyToFile(privateKey, keyID, privateKeyPath); err != nil {
		t.Fatalf("failed to save private key: %v", err)
	}

	// Create a KeyManager with that will load the public key we just saved
	// Use TrustLevelNoX5C as testing keys without certificates
	ctx := context.Background()
	registryURL, _ := url.Parse("testdata/platform-registry/eblsolutionproviders.csv")
	config := NewConfig(registryURL, tempDir, TrustLevelNoX5C, 30*time.Second, true)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	km, err := NewKeyManager(ctx, config, logger)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	// Test 1: Verify public key was loaded
	compositeKeyID := hostname + ":" + keyID
	key, exists := km.manualKeys[compositeKeyID]
	if !exists {
		t.Fatalf("expected manual key %s to be loaded", compositeKeyID)
	}

	// Verify it's a public key
	var raw any
	if err := jwk.Export(key, &raw); err != nil {
		t.Fatalf("failed to export key: %v", err)
	}

	pubKey, ok := raw.(ed25519.PublicKey)
	if !ok {

		t.Errorf("unexpected key type: %T", raw)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		t.Errorf("expected public key size %d, got %d", ed25519.PublicKeySize, len(pubKey))
	}

	// Verify metadata
	metadata, exists := km.metadata[compositeKeyID]
	if !exists {
		t.Fatalf("expected metadata for key %s", compositeKeyID)
	}

	if metadata.Hostname != hostname {
		t.Errorf("expected domain %s, got %s", hostname, metadata.Hostname)
	}

	if metadata.TrustLevel != TrustLevelNoX5C {
		t.Errorf("expected trust level %d (TrustLevelNoX5C), got %d", TrustLevelNoX5C, metadata.TrustLevel)
	}

	// Verify key source - should be manual
	if metadata.KeySource != KeySourceManual {
		t.Errorf("expected key source %d (KeySourceManual), got %d", KeySourceManual, metadata.KeySource)
	}

	// verify private key can't accidentally be loaded in a file named *.public.jwk

	// mv *.private.jwk *.public.jwk
	if err := os.Rename(privateKeyPath, publicKeyPath); err != nil {
		t.Fatalf("failed to rename private key file: %v", err)
	}

	// Create a new KeyManager to load the renamed file
	km, err = NewKeyManager(ctx, config, logger)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	// Verify key was NOT loaded (should be rejected due to private key validation)
	if _, exists := km.manualKeys[compositeKeyID]; exists {
		t.Errorf("private key was loaded from .public.jwk file - validation failed")
		return
	}

	// Verify no keys were loaded (the private key should have been rejected)
	if len(km.manualKeys) != 0 {
		t.Errorf("expected 0 keys loaded, got %d", len(km.manualKeys))
	}

	t.Logf("✓ Ed25519 private key was correctly rejected from .public.jwk file")
}
