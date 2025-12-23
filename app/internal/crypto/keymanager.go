// these functions handle discovering, caching, and validating public keys
// from eBL solution providers for JWS signature verification.
//
// # DCSA Signature Verification Process
//
// The KeyManager implements DCSA's standardized signature verification process:
//
// 1) Decode the JWS (handled by caller)
// 2) Match the key id to an existing digital certificate
// 3) Check that the digital certificate is from the correct platform
// 4) Check that the signature matches with the public key (handled by caller)
// 5) Validate checksums in the JWS payload (handled by caller)
//
// # Platform Identification  (TODO: confirm with DCSA)
//
// Platform identification is achieved through JWS signature verification combined with DCSA's approved
// domain registry. This registry is used below as the **authorization allowlist
//
// # Trust Hierarchy
// DCSA says 'The use of EV or OV certificates is recommended by DCSA for digital signatures,
// but it is not a conformance requirement.'
//
// this app implements a trust hierarchy for key sources - 1 is highest trust, 5 is lowest (see below)
//
// # Key ID (kid) Usage
//
// DCSA Digital Signatures guide states:
// "When the certificates are exchanged, the parties must agree on how to identify the key pair in
// question. This is the key id (kid) used in the digital signature. A common approach (e.g. in
// OpenID Connect) is to generate a JWK thumbprint of the public key. Therefore, this is a
//
// TODO:
// - Load manual keys from configured directory (Trust Level 1)
// - Certificate validation and trust level assignment
// - Revocation checking (OCSP/CRL)

package crypto

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// TrustLevel represents the trust level of a key source.
// Lower numbers indicate higher trust.
// levels 1 or 2 are  recommended for production eBL transfers.
type TrustLevel int

const (
	// TrustLevelManual represents manually configured keys (highest trust).
	//	- Keys exchanged out of band stored locally by the operator
	//	- No automatic refresh - requires manual updates
	//	- Highest trust - operator has verified authenticity
	TrustLevelManual TrustLevel = 1

	// TrustLevelOVEV represents keys from HTTPS endpoint with OV/EV certificate.
	//	- Provides non-repudiation through organizational identity validation.
	//	- Keys fetched from HTTPS JWK endpoint with Organization Validation (OV) or
	//      Extended Validation (EV) certificate
	//	- Certificate validation confirms organizational identity
	//	- Auto-refreshed from remote endpoint
	TrustLevelOVEV TrustLevel = 2

	// TrustLevelDV represents keys from HTTPS endpoint with DV certificate.
	//	- Validates domain ownership but not organizational identity.
	//	- Keys from HTTPS endpoint with Domain Validation (DV) certificate
	//	- Validates domain ownership but not organizational identity
	TrustLevelDV TrustLevel = 3

	// TrustLevelCNMatch represents keys from endpoint where TLS certificate
	// CN/SAN matches the expected domain
	//	- Provides basic transport security.
	// 	- Fallback when certificate validation level cannot be determined.
	TrustLevelCNMatch TrustLevel = 4

	// TrustLevelSelfSigned represents keys from endpoint with self-signed certificate.
	// - No third-party validation of identity.
	// - Testing/development only
	TrustLevelSelfSigned TrustLevel = 5
)

// eblSolutionProvider represents an eBL solution provider from the DCSA registry.
type eblSolutionProvider struct {

	// Name is the human-readable name of the platform (e.g., "Wave BL").
	Name string

	// Code is an short code for the platform (e.g., "WAVE").
	Code string

	// Domain is the approved domain for this platform (e.g., "https://wave.example.com").
	URL *url.URL

	// Description
	Description string
}

// KeyMetadata contains metadata about a cached key.
type KeyMetadata struct {
	// Domain is the domain this key belongs to (e.g., "wave.example.com").
	Domain string

	// TrustLevel is the trust level of this key.
	TrustLevel TrustLevel

	// CertificateChain is the TLS certificate chain
	CertificateChain []*x509.Certificate

	// CertificateFingerprint is the SHA-256 fingerprint of the leaf certificate.
	CertificateFingerprint string

	// LastRefresh is the timestamp of the last successful refresh.
	LastRefresh time.Time

	// ExpiresAt is the expiry time of the key (if known from x5c or certificate).
	ExpiresAt *time.Time

	// RevocationCheckTime is the timestamp of the last revocation check.
	RevocationCheckTime time.Time

	// RevocationStatus indicates whether the certificate is revoked.
	// Values: "good", "revoked", "unknown", "error"
	RevocationStatus string

	// CertificateSubject is the subject (CN/SAN) from the certificate.
	CertificateSubject string

	// CertificateIssuer is the issuer from the certificate.
	CertificateIssuer string
}

// KeyManager manages public keys for JWS verification.
type KeyManager struct {
	// eblSolutionProviders is the registry of DCSA-approved platforms.
	eblSolutionProviders map[string]*eblSolutionProvider // keyed by domain

	// manualKeys stores manually configured keys (Trust Level 1).
	manualKeys map[string]jwk.Key // keyed by domain

	// jwkCache is the auto-refreshing cache for remote JWK sets.
	jwkCache *jwk.Cache

	// metadata stores trust level and certificate information for each domain.
	metadata map[string]*KeyMetadata // keyed by domain

	// httpClient is the HTTP client used for fetching JWK sets.
	httpClient *http.Client

	// logger is used for structured logging.
	logger *slog.Logger

	// mu protects concurrent access to maps.
	mu sync.RWMutex

	// config holds the KeyManager configuration.
	config *Config
}

// Config holds configuration for the KeyManager.
type Config struct {
	// eblSolutionProvidersRegistryURL is the URL to fetch the DCSA approved platforms list.
	// e.g. https://github.com/dcsaorg/DCSA-OpenAPI/raw/master/reference-data/eblsolutionproviders-v3.0.0.csv
	eblSolutionProvidersRegistryURL *url.URL

	// ManualKeysDir is the directory containing manually configured keys.
	// Files should be named: {domain}.jwk.json or {domain}.pem
	ManualKeysDir string

	// MinTrustLevel is the minimum acceptable trust level.
	// Keys below this level will be rejected.
	MinTrustLevel TrustLevel

	// HTTPTimeout is the timeout for HTTP requests to fetch JWK sets.
	HTTPTimeout time.Duration

	// SkipJWKCache disables JWK cache initialization (useful for testing)
	SkipJWKCache bool
}

// NewConfig creates a new Config with the specified parameters.
func NewConfig(registryURL *url.URL, manualKeysDir string, minTrustLevel TrustLevel, httpTimeout time.Duration, skipJWKCache bool) *Config {
	return &Config{
		eblSolutionProvidersRegistryURL: registryURL,
		ManualKeysDir:                   manualKeysDir,
		MinTrustLevel:                   minTrustLevel,
		HTTPTimeout:                     httpTimeout,
		SkipJWKCache:                    skipJWKCache,
	}
}

// NewKeyManager creates a new KeyManager with the given configuration.
func NewKeyManager(ctx context.Context, config *Config, logger *slog.Logger) (*KeyManager, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	// check for nil url
	if config.eblSolutionProvidersRegistryURL == nil {
		return nil, fmt.Errorf("eblSolutionProvidersRegistryURL is required")
	}

	if config.MinTrustLevel == 0 {
		return nil, fmt.Errorf("MinTrustLevel is required")
	}
	if config.HTTPTimeout == 0 {
		return nil, fmt.Errorf("HTTPTimeout is required")
	}

	// Initialize the key manager
	km := &KeyManager{
		config:               config,
		eblSolutionProviders: make(map[string]*eblSolutionProvider),
		manualKeys:           make(map[string]jwk.Key),
		metadata:             make(map[string]*KeyMetadata),
		logger:               logger,
	}

	km.httpClient = &http.Client{
		Timeout: km.config.HTTPTimeout,
	}

	logger.Info("initializing KeyManager",
		slog.String("REGISTRY_URL", config.eblSolutionProvidersRegistryURL.String()),
		slog.Int("MIN_TRUST_LEVEL", int(config.MinTrustLevel)),
		slog.Bool("SKIP_JWK_CACHE", config.SkipJWKCache))

	// Load DCSA registry of approved eBL solution providers
	if err := km.loadEbLSolutionProviders(ctx); err != nil {
		return nil, fmt.Errorf("failed to load DCSA registry: %w", err)
	}

	km.logger.Info("DCSA registry loaded", slog.Int("providers", len(km.eblSolutionProviders)))

	// Initialize JWK cache
	// TODO: async?
	if !config.SkipJWKCache {
		if err := km.initJWKCache(ctx); err != nil {
			return nil, fmt.Errorf("failed to init JWK cache: %w", err)
		}

		km.logger.Debug("JWK cache initialized")
	} else {
		km.logger.Info("JWK cache initialization skipped")
	}

	return km, nil
}

// loadEbLSolutionProviders fetches the DCSA registry of approved domains.
// this function assumes the same csv as can be found at https://github.com/dcsaorg/DCSA-OpenAPI/raw/master/reference-data/eblsolutionproviders-v3.0.0.csv
// (Name,Code,URL,Description)
//
// TODO: check with DCSA if they will maintain this register and - if they do - how it will be shared
// if it is the csv file some more robust checks are probably appropriate below.
// TODO: consider storing this on the db in addition to the cache in case of outage
// TODO: we may need a mechanism to immediately refresh the registry in case of changes
func (km *KeyManager) loadEbLSolutionProviders(ctx context.Context) error {
	km.logger.Info("loading DCSA registry",
		slog.String("url", km.config.eblSolutionProvidersRegistryURL.String()))

	// Fetch the CSV data (from file or HTTP)
	data, err := km.fetchRegistryData(ctx)
	if err != nil {
		return err
	}

	// Parse the CSV data
	reader := csv.NewReader(bytes.NewReader(data))
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to parse DCSA registry csv: %w", err)
	}

	for _, record := range records {
		// skip header row
		if record[0] == "Name" {
			continue
		}
		if len(record) != 4 {
			return fmt.Errorf("invalid DCSA registry record: %v", record)
		}

		eblSolutionProvider := &eblSolutionProvider{}

		if record[0] == "" {
			return fmt.Errorf("invalid DCSA registry record - name not set: %v", record)
		}
		eblSolutionProvider.Name = record[0]

		if record[1] == "" {
			return fmt.Errorf("invalid DCSA registry record - code not set: %v", record)
		}
		eblSolutionProvider.Code = record[1]

		if record[2] == "" {
			return fmt.Errorf("invalid DCSA registry record - url not set: %v", record)
		}
		url, err := url.Parse(record[2])
		if err != nil {
			return fmt.Errorf("invalid DCSA registry record - invalid url: %v", record)
		}
		eblSolutionProvider.URL = url

		domain := eblSolutionProvider.URL.Hostname()

		eblSolutionProvider.Description = record[3]

		km.eblSolutionProviders[domain] = eblSolutionProvider
	}

	return nil
}

// fetchRegistryData fetches the registry data from either a local file or HTTP URL.
func (km *KeyManager) fetchRegistryData(ctx context.Context) ([]byte, error) {
	switch km.config.eblSolutionProvidersRegistryURL.Scheme {
	case "https", "http":
		req, err := http.NewRequestWithContext(ctx, "GET", km.config.eblSolutionProvidersRegistryURL.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create DCSA registry request: %w", err)
		}
		res, err := km.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch DCSA registry: %w", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to fetch DCSA registry: status %d", res.StatusCode)
		}

		return io.ReadAll(res.Body)

	case "":
		// Plain file path (no scheme)
		return os.ReadFile(km.config.eblSolutionProvidersRegistryURL.String())

	default:
		return nil, fmt.Errorf("unsupported URL scheme: %s (expected https:// or a local directory path)", km.config.eblSolutionProvidersRegistryURL.Scheme)
	}
}

// initJWKCache initializes the JWK cache and registers all eBL solution provider JWK endpoints.
// The cache will automatically fetch and refresh JWK sets from each provider's .well-known/jwks.json endpoint.
//
// TODO: the well-known JWK endpoint URL is based on RFC 8615 - what are the eBL solution providers planning/
// TODO: cache refresh intervals should be configurable
// TODO: do we need to support  https://{domain}/.well-known/openid-configuration ?
func (km *KeyManager) initJWKCache(ctx context.Context) error {
	km.logger.Info("initializing JWK cache",
		slog.Int("providers", len(km.eblSolutionProviders)))

	client := httprc.NewClient()

	cache, err := jwk.NewCache(ctx, client)
	if err != nil {
		// Check if it's a context error (recoverable)
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			km.logger.Warn("JWK cache creation timed out - will retry in background",
				slog.String("error", err.Error()))
			return nil // Recoverable: start server anyway
		}
		// System error - fatal
		return fmt.Errorf("failed to create JWK cache: %w", err)
	}
	km.jwkCache = cache

	successCount := 0
	// Register each eBL solution provider's JWK endpoint
	for domain := range km.eblSolutionProviders {
		jwkURL := fmt.Sprintf("https://%s/.well-known/jwks.json", domain)

		err := km.jwkCache.Register(ctx, jwkURL,
			jwk.WithMinInterval(15*time.Minute),
			jwk.WithMaxInterval(24*time.Hour),
		)
		if err != nil {
			km.logger.Warn("failed to register JWK endpoint",
				slog.String("domain", domain),
				slog.String("jwk_url", jwkURL),
				slog.String("error", err.Error()))
			continue
		}

		successCount++
		km.logger.Debug("registered JWK endpoint",
			slog.String("domain", domain),
			slog.String("jwk_url", jwkURL))
	}

	// Log summary - but don't fail if no endpoints registered
	// (they might all be using manual keys, or auto-retry will fix it)
	km.logger.Info("JWK cache registration complete",
		slog.Int("registered", successCount),
		slog.Int("total_providers", len(km.eblSolutionProviders)))

	return nil
}
