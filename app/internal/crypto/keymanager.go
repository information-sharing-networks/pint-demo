// keymanager.go handles discovering, caching, and validating public keys
// from eBL solution providers for JWS signature verification.
//
// eBL signatures may be stored externally from this app in order to track transfers, provide an externally verifiable audit trail and so on.
// x5c headers in JWS are OPTIONAL but recommended for non-repudiation (enables offline verification and legal disputes).
// For real-time verification, keys are fetched from JWK endpoints or stored certificates using the kid header.
//
// # for details on the trust model and the signature verification process see envelope_verification.go where the process is implemented.
// The KeyManager implements functions to support DCSA's recommended signature verification process.
package crypto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// KeySource represents how a key was obtained (manual vs JWK endpoint).
type KeySource int

const (
	// KeySourceManual represents keys manually configured by an operator.
	// - Keys exchanged out of band and stored locally
	// - No automatic refresh - requires manual updates
	KeySourceManual KeySource = 1

	// KeySourceJWKEndpoint represents keys fetched from a JWK endpoint.
	// Keys auto-refreshed from remote HTTPS endpoint (e.g., /.well-known/jwks.json)
	KeySourceJWKEndpoint KeySource = 2
)

// eblSolutionProvider represents an eBL solution provider from the DCSA registry.
type eblSolutionProvider struct {

	// Name is the human-readable name of the platform (e.g., "Wave BL").
	Name string

	// Code is an short code for the platform (e.g., "WAVE").
	Code string

	// URL is the approved web site for this platform (e.g., "https://wave.example.com").
	URL *url.URL

	// Description
	Description string
}

// KeyMetadata contains metadata about a cached key.
type KeyMetadata struct {
	// Hostname is the host this key belongs to (e.g., "wave.example.com").
	Hostname string

	// TrustLevel is the trust level of this key based on certificate validation.
	// Determined by x5c certificate chain
	TrustLevel TrustLevel

	// KeySource indicates how this key was obtained (manual, JWK endpoint)
	KeySource KeySource

	// CertificateChain is the X.509 certificate chain from x5c (if present).
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
	// Files should be JWK and named: {hostname}.jwk
	ManualKeysDir string

	// HTTPTimeout is the timeout for HTTP requests to fetch JWK sets.
	HTTPTimeout time.Duration

	// SkipJWKCache disables JWK cache initialization (useful for testing)
	SkipJWKCache bool
}

// the manual key naming convention is domain.public.jwk
// TODO: support for a custom JWK field, "ext_domain": "example.com", rather than filename?
// TODO consider support for PEMs?
const (
	publicJWKFileNameSuffix = ".public.jwk"
)

// NewConfig creates a new keymanager Config with the specified parameters.
func NewConfig(registryURL *url.URL, manualKeysDir string, httpTimeout time.Duration, skipJWKCache bool) *Config {
	return &Config{
		eblSolutionProvidersRegistryURL: registryURL,
		ManualKeysDir:                   manualKeysDir,
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
		slog.Bool("SKIP_JWK_CACHE", config.SkipJWKCache))

	// Load DCSA registry of approved eBL solution providers
	if err := km.loadEbLSolutionProviders(ctx); err != nil {
		return nil, fmt.Errorf("failed to load DCSA registry: %w", err)
	}

	km.logger.Info("DCSA registry loaded", slog.Int("providers", len(km.eblSolutionProviders)))

	// Load manual keys (Trust Level 1)
	if config.ManualKeysDir != "" {
		if err := km.loadManualKeys(); err != nil {
			return nil, fmt.Errorf("failed to load manual keys: %w", err)
		}
		km.logger.Info("manual keys loaded", slog.Int("keys", len(km.manualKeys)))
	}

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

// loadManualKeys loads manually configured JWK public keys from the configured directory.
// The expected filename is domain.public.jwk, however, the file content is validated to make sure it is a public key.
// TODO: x5c - validate cert chain
// TODO: tighten up the association between domain and key - embed in the key file?
// TODO: confirm with DCSA if we can rely on the reference data to 'allow list' domains.
func (km *KeyManager) loadManualKeys() error {
	km.logger.Info("loading manual keys", slog.String("dir", km.config.ManualKeysDir))

	// Check if directory exists
	info, err := os.Stat(km.config.ManualKeysDir)
	if err != nil {
		if os.IsNotExist(err) {
			km.logger.Error("manual keys directory does not exist", slog.String("dir", km.config.ManualKeysDir))
			return fmt.Errorf("specified manual keys directory (%v) does not exist", km.config.ManualKeysDir)
		}
		return fmt.Errorf("failed to stat manual keys directory: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("manual keys path is not a directory: %s", km.config.ManualKeysDir)
	}

	// Read all files in directory
	entries, err := os.ReadDir(km.config.ManualKeysDir)
	if err != nil {
		return fmt.Errorf("failed to read manual keys directory: %w", err)
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()

		// Only process .jwk files
		if !strings.HasSuffix(filename, publicJWKFileNameSuffix) {
			km.logger.Debug("skipping non-public-JWK file", slog.String("file", filename))
			continue
		}

		// Extract hostname from filename: eblplatform.example.com.jwk -> eblplatform.example.com
		hostname := strings.TrimSuffix(filename, publicJWKFileNameSuffix)
		if hostname == "" {
			km.logger.Warn("invalid manual key filename", slog.String("file", filename))
			continue
		}

		// Check if domain is in approved registry
		if _, exists := km.eblSolutionProviders[hostname]; !exists {
			km.logger.Warn("manual key for unapproved domain - skipping",
				slog.String("domain", hostname),
				slog.String("file", filename))
			continue
		}

		// Read and parse JWK file using os.Root for directory traversal protection
		root, err := os.OpenRoot(km.config.ManualKeysDir)
		if err != nil {
			km.logger.Warn("failed to open manual keys directory",
				slog.String("dir", km.config.ManualKeysDir),
				slog.String("error", err.Error()))
			continue
		}
		defer root.Close()

		data, err := root.ReadFile(filename)
		if err != nil {
			km.logger.Warn("failed to read manual key file",
				slog.String("file", filename),
				slog.String("error", err.Error()))
			continue
		}

		// Parse as JWK Set
		keySet, err := jwk.Parse(data)
		if err != nil {
			km.logger.Warn("failed to parse manual key file",
				slog.String("file", filename),
				slog.String("error", err.Error()))
			continue
		}

		// Store each key in the set
		for i := 0; i < keySet.Len(); i++ {
			key, ok := keySet.Key(i)
			if !ok {
				continue
			}

			kid, ok := key.KeyID()
			if !ok || kid == "" {
				km.logger.Warn("manual key missing kid",
					slog.String("domain", hostname),
					slog.Int("key_index", i))
				continue
			}

			// Only allow RSA public keys or Ed25519 public keys
			var raw any
			if err := jwk.Export(key, &raw); err != nil {
				km.logger.Warn("failed to export manual key",
					slog.String("domain", hostname),
					slog.String("kid", kid),
					slog.String("error", err.Error()))
				continue
			}

			isValidPublicKey := false
			var keyType string

			switch v := raw.(type) {
			case *rsa.PublicKey:
				isValidPublicKey = true
				keyType = "RSA public key"
			case ed25519.PublicKey:
				isValidPublicKey = true
				keyType = "Ed25519 public key"
			case *rsa.PrivateKey:
				keyType = "RSA private key"
			case ed25519.PrivateKey:
				keyType = fmt.Sprintf("Ed25519 private key (%d bytes)", len(v))
			default:
				keyType = fmt.Sprintf("unknown type: %T", v)
			}

			if !isValidPublicKey {
				km.logger.Warn("the key in the .public.jwk file is not a RSA or ED25519 public key - skipping",
					slog.String("domain", hostname),
					slog.String("kid", kid),
					slog.String("file", filename),
					slog.String("key_type", keyType))
				continue
			}

			km.logger.Debug("validated public key",
				slog.String("domain", hostname),
				slog.String("kid", kid),
				slog.String("key_type", keyType))

			// Determine trust level based on x5c certificate (if present)
			// TODO: Check for x5c in key and validate certificate chain to determine actual trust level
			trustLevel := TrustLevelNoX5C

			// Store key with composite key: domain:kid
			keyID := fmt.Sprintf("%s:%s", hostname, kid)
			km.manualKeys[keyID] = key

			// Store metadata
			km.metadata[keyID] = &KeyMetadata{
				Hostname:    hostname,
				TrustLevel:  trustLevel,
				KeySource:   KeySourceManual,
				LastRefresh: time.Now(),
			}

			km.logger.Debug("loaded manual key",
				slog.String("domain", hostname),
				slog.String("kid", kid),
				slog.Int("trust_level", int(trustLevel)))
		}
	}

	return nil
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
			return nil
		}
		// fatal error
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
