package crypto

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

// TODO: end2end test with jwk endpoint
func TestKeyManager_LoadRegistry(t *testing.T) {
	ctx := context.Background()
	url, _ := url.Parse("../../testdata/eblsolutionproviders.csv")
	config := NewConfig(url, "config/manual-keys", TrustLevelDV, 30*time.Second, true)

	// Create a test logger that discards output
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	km, err := NewKeyManager(ctx, config, logger)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	// Verify that providers were loaded
	if len(km.eblSolutionProviders) != 3 {
		t.Fatalf("expected 3 eBL solution providers, got %d", len(km.eblSolutionProviders))
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
			urlStr:  "../../testdata/eblsolutionproviders.csv",
			wantErr: false,
		},
		{
			name:    "file not found",
			urlStr:  "../../testdata/nonexistent.csv",
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
