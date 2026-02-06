// keymanager.go handles discovering, caching, and validating the public keys used to verify PINT JWS signatures
//
// The keymanager supports two ways of configuring public keys:
//   - JWKS endpoint: the keymanager will fetch the public keys from the JWKS endpoint
//   - Manual key: the keymanager will load the public keys received ou-of-band
//     from the configured directory at startup and use it to verify signatures.
//
// # manual keys
// The manual keys are loaded from the configured directory at startup and are not refreshed.
// The directory should contain single public keys in JWK format.
//
// JWKS files containing multipke keys are not supported - if you need key rotation,
// it is recommended to use a JWKS endpoint instead.
//
// Keys are mapped to a platform by by looking up the kid in the platform registry.
//
// # platform registry
// The keymanager relies on a registry of PINT participants.
//
// The registry is used to establish:
//   - Which platforms are authorized to participate in the PINT network
//   - The JWKS endpoint for each platform (e.g., "https://wavebl.com/.well-known/jwks.json")
//   - and (where no JWKS endpoint is specified) the kid of the manually configured key for the platform
//
// Platforms not in the registry will not have their keys loaded, and their messages will be rejected.
//
// TODO: for the demo app the registry is a simple CSV file, but in a real deployment the registry would be served
// from a secure endpoint and cover all participants in the PINT network.
// We would also need to implement a mechanism to refresh the registry in case of changes (for now it is loaded at startup and not refreshed)
//
// TODO: do we need to keep a record of expired keys so we can validate signatures on old documents?
package pint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/csv"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// eblSolutionProvider represents an eBL solution provider from the DCSA registry.
// this can be a carrier, software provider or other entity that is approved to participate in the PINT network
type eblSolutionProvider struct {

	// Code is the DCSA code for the platform (e.g., "WAVE", "CARX")
	Code string

	// Site is the URL of the provider's website (e.g., "https://wavebl.com")
	Site string

	// JWKSEndpoint is the full URL for the JWKS endpoint
	// e.g., "https://wavebl.com/.well-known/jwks.json"
	JWKSEndpoint string

	// ManualKeyID is the kid of the manually configured public key for this provider.
	// this implementation expects the kid to be the thumbprint of the public key.
	//
	// Assuming a jwk with the corresponding kid is found in the manual keys directory
	// the key will be cached and associated with this provider.
	//
	// It is not allowed to set both the JWKSEndpoint and ManualKeyID for the same provider -
	// choose one or the other.
	ManualKeyID string
}

// PublicKeyInfo contains a public key and its metadata for logging.
// used by the keymanager to cache public keys from manual configured JWKs
type PublicKeyInfo struct {

	// Provider is the eblSolutionProvider that this key is associated with
	Provider *eblSolutionProvider

	// Key is the public key that was retrieved from the JWK endpoint or from manual configuration
	Key jwk.Key

	// KeyID is the KID of the public key
	// this implementation expects the KID to be the thumbprint of the public key (see jwk.go)
	KeyID string
}

// KeyManager manages public keys for JWS verification.
type KeyManager struct {
	// eblSolutionProviders is the registry of DCSA-approved platforms.
	// Keyed by DCSA platform code (e.g., "WAVE", "CARX", "EDOX")
	eblSolutionProviders map[string]*eblSolutionProvider

	// manualKeys stores any manually configured keys (loaded from filesystem).
	// Keyed by kid (key ID from the JWK).
	manualKeys map[string]*PublicKeyInfo

	// jwkCache is the auto-refreshing cache for remote JWK sets.
	// This is the source of for remote keys fetched from JWKS endpoints.
	jwkCache *jwk.Cache

	// httpClient is the HTTP client used for fetching JWK sets.
	httpClient *http.Client

	// logger is used for structured logging.
	logger *slog.Logger

	// mu protects concurrent access to maps.
	// for future proofing (currently the maps are only written at startup)
	mu sync.RWMutex

	// config holds the KeyManager configuration.
	config *KeyManagerConfig
}

// KeyManagerConfig holds configuration for the KeyManager.
type KeyManagerConfig struct {
	// eblSolutionProvidersRegistryPath is the URL to fetch the DCSA approved platforms list.
	eblSolutionProvidersRegistryPath string

	// ManualKeysDir is the directory containing manually configured keys.
	// Each file must contain exactly ONE key (files with multiple keys are rejected).
	// For key rotation, use a JWKS endpoint instead.
	// Supported file extensions: .jwk, .jwks, .jwks.json
	ManualKeysDir string

	// HTTPTimeout is the timeout for HTTP requests to fetch JWK sets.
	HTTPTimeout time.Duration

	// SkipJWKCache disables JWK cache initialization (useful for testing)
	SkipJWKCache bool

	// JWKCacheMinRefreshInterval is the minimum interval between JWK cache refreshes.
	JWKCacheMinRefreshInterval time.Duration

	// JWKCacheMaxRefreshInterval is the maximum interval between JWK cache refreshes.
	JWKCacheMaxRefreshInterval time.Duration
}

// NewKeymanagerConfig creates a new keymanager Config with the specified parameters.
func NewKeymanagerConfig(RegistryPath string, manualKeysDir string, httpTimeout time.Duration, skipJWKCache bool, minRefreshInterval, maxRefreshInterval time.Duration) *KeyManagerConfig {
	return &KeyManagerConfig{
		eblSolutionProvidersRegistryPath: RegistryPath,
		ManualKeysDir:                    manualKeysDir,
		HTTPTimeout:                      httpTimeout,
		SkipJWKCache:                     skipJWKCache,
		JWKCacheMinRefreshInterval:       minRefreshInterval,
		JWKCacheMaxRefreshInterval:       maxRefreshInterval,
	}
}

// NewKeyManager creates a new KeyManager with the given configuration.
func NewKeyManager(ctx context.Context, config *KeyManagerConfig, logger *slog.Logger) (*KeyManager, error) {
	if config == nil {
		return nil, NewInternalError("config is nil")
	}
	if logger == nil {
		return nil, NewInternalError("logger cannot be nil")
	}

	_, err := url.Parse(config.eblSolutionProvidersRegistryPath)
	if err != nil {
		return nil, NewInternalError("failed to parse eblSolutionProvidersRegistryPath")
	}

	if config.HTTPTimeout == 0 {
		return nil, NewInternalError("HTTPTimeout is required")
	}

	// Initialize the key manager
	km := &KeyManager{
		config:               config,
		eblSolutionProviders: make(map[string]*eblSolutionProvider),
		manualKeys:           make(map[string]*PublicKeyInfo),
		logger:               logger,
	}

	km.httpClient = &http.Client{
		Timeout: km.config.HTTPTimeout,
	}

	logger.Info("initializing KeyManager",
		slog.String("DCSA_REGISTRY_PATH", config.eblSolutionProvidersRegistryPath),
		slog.Bool("SKIP_JWK_CACHE", config.SkipJWKCache))

	// Load DCSA registry of approved eBL solution providers
	if err := km.loadEbLSolutionProviders(); err != nil {
		return nil, WrapRegistryError(err, "failed to load DCSA registry")
	}

	km.logger.Info("DCSA registry loaded", slog.Int("providers", len(km.eblSolutionProviders)))

	// Load manual keys
	if config.ManualKeysDir != "" {
		if err := km.loadManualKeys(); err != nil {
			return nil, WrapKeyError(err, "failed to load manual keys")
		}
		km.logger.Info("manual keys loaded", slog.Int("keys", len(km.manualKeys)))
	}

	// Initialize JWK cache
	if !config.SkipJWKCache {
		if err := km.initJWKCache(ctx); err != nil {
			return nil, WrapKeyError(err, "failed to init JWK cache")
		}

		km.logger.Debug("JWK cache initialized")
	} else {
		km.logger.Info("JWK cache initialization skipped")
	}

	return km, nil
}

// loadEbLSolutionProviders fetches the DCSA registry of approved platforms
//
// For the demo this is a csv file (code, site, jwks_endpoint, manual_key_id)
// but in a real deployment this would be served from a secure endpoint
func (k *KeyManager) loadEbLSolutionProviders() error {
	k.logger.Info("loading DCSA registry",
		slog.String("url", k.config.eblSolutionProvidersRegistryPath))

	// Fetch the CSV data
	data, err := os.ReadFile(k.config.eblSolutionProvidersRegistryPath)
	if err != nil {
		return err
	}

	// Parse the CSV data
	reader := csv.NewReader(bytes.NewReader(data))
	records, err := reader.ReadAll()
	if err != nil {
		return WrapRegistryError(err, "failed to parse registry csv")
	}

	for _, record := range records {
		// skip header row
		if record[0] == "Code" {
			continue
		}
		if len(record) != 4 {
			return NewRegistryError(fmt.Sprintf("invalid registry record: %v", record))
		}

		// DCSA code
		code := record[0]
		if code == "" {
			return NewRegistryError(fmt.Sprintf("invalid registry record - code not set: %v", record))
		}

		// web site
		site := record[1]
		if site == "" {
			return NewRegistryError(fmt.Sprintf("invalid registry record - site not set: %v", record))
		}

		_, err := url.Parse(site)
		if err != nil {
			return NewRegistryError(fmt.Sprintf("invalid registry record - invalid website: %v", record))
		}

		jwksEndpoint := record[2]

		manualKeyID := record[3]

		if jwksEndpoint == "" && manualKeyID == "" {
			return NewRegistryError(fmt.Sprintf("invalid registry record - no jwks_endpoint or manual_key_id: %v", record))
		}

		if jwksEndpoint != "" && manualKeyID != "" {
			return NewRegistryError(fmt.Sprintf("invalid registry record - both jwks_endpoint and manual_key_id set: %v", record))
		}

		if jwksEndpoint != "" {
			_, err := url.Parse(jwksEndpoint)
			if err != nil {
				return NewRegistryError(fmt.Sprintf("invalid registry record - invalid url: %v", record))
			}
		}

		provider := &eblSolutionProvider{
			Code:         code,
			Site:         site,
			JWKSEndpoint: jwksEndpoint,
			ManualKeyID:  manualKeyID,
		}

		// Key by DCSA platform code (e.g., "WAVE", "CARX")
		if k.eblSolutionProviders[code] != nil {
			return NewRegistryError(fmt.Sprintf("duplicate DCSA platform code in registry: %s", code))
		}
		k.eblSolutionProviders[code] = provider
	}

	return nil
}

// loadManualKeys loads manually configured JWK public keys from the configured directory.
//
// Manual key files must contain one key. Files with multiple keys will be rejected.
// For key rotation, use a JWKS endpoint instead of manual configuration.
//
// Supported file extensions: .jwk, .jwks, .jwks.json
func (k *KeyManager) loadManualKeys() error {
	k.logger.Info("loading manual keys", slog.String("dir", k.config.ManualKeysDir))

	// Check if directory exists
	info, err := os.Stat(k.config.ManualKeysDir)
	if err != nil {
		if os.IsNotExist(err) {
			k.logger.Error("manual keys directory does not exist", slog.String("dir", k.config.ManualKeysDir))
			return NewValidationError(fmt.Sprintf("specified manual keys directory (%v) does not exist", k.config.ManualKeysDir))
		}
		return WrapKeyError(err, "failed to stat manual keys directory")
	}

	if !info.IsDir() {
		return NewValidationError(fmt.Sprintf("manual keys path is not a directory: %s", k.config.ManualKeysDir))
	}

	// Read all files in directory
	entries, err := os.ReadDir(k.config.ManualKeysDir)
	if err != nil {
		return WrapKeyError(err, "failed to read manual keys directory")
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()

		// Only process .jwk, .jwks, or .jwks.json files
		isJWKFile := strings.HasSuffix(filename, ".jwk") ||
			strings.HasSuffix(filename, ".jwks") ||
			strings.HasSuffix(filename, ".jwks.json")

		if !isJWKFile {
			k.logger.Debug("skipping: file non-JWK file", slog.String("file", filename))
			continue
		}

		// Read file
		root, err := os.OpenRoot(k.config.ManualKeysDir)
		if err != nil {
			return WrapKeyError(err, "failed to open manual keys directory")
		}
		defer root.Close()

		data, err := root.ReadFile(filename)
		if err != nil {
			if os.IsPermission(err) {
				k.logger.Debug("skipping: file permission denied",
					slog.String("file", filename))
			} else {
				k.logger.Error("skipping: file failed to read manual key file",
					slog.String("file", filename),
					slog.String("error", err.Error()))
			}
			continue
		}

		// Parse as JWK Set
		keySet, err := jwk.Parse(data)
		if err != nil {
			k.logger.Error("skipping: file failed to parse manual key data",
				slog.String("file", filename),
				slog.String("error", err.Error()))
			continue
		}

		// Manual keys must be single JWK files, not JWKS with multiple keys
		if keySet.Len() == 0 {
			k.logger.Error("skipping: file manual key file contains no keys",
				slog.String("file", filename))
			continue
		}
		if keySet.Len() > 1 {
			k.logger.Error("skipping: file manual key file contains multiple keys",
				slog.String("file", filename),
				slog.Int("key_count", keySet.Len()),
				slog.String("hint", "only single key files are supported for manual configuration - use a JWKS endpoint for key rotation"))
			continue
		}

		key, _ := keySet.Key(0)

		// get key ID
		keyID, ok := key.KeyID()
		if !ok || keyID == "" {
			k.logger.Error("skipping: file manual key missing kid",
				slog.String("file", filename))
			continue
		}

		// get the key material
		var raw any
		if err := jwk.Export(key, &raw); err != nil {
			k.logger.Error("skipping: file failed to export manual key from file",
				slog.String("file:", filename),
				slog.String("error", err.Error()))
			continue
		}

		// Only allow RSA public keys or Ed25519 public keys
		isValidPublicKey := false
		var keyType string

		switch v := raw.(type) {
		case *rsa.PublicKey:
			isValidPublicKey = true
			keyType = "RSA public key"
		case ed25519.PublicKey:
			isValidPublicKey = true
			keyType = "Ed25519 public key"
		default:
			keyType = fmt.Sprintf("%T", v)
		}

		if !isValidPublicKey {
			k.logger.Warn("skipping: file does not contain a RSA or ED25519 public key - skipping",
				slog.String("file", filename),
				slog.String("key_type", keyType))
			continue
		}

		// Find registry entry with matching manual key id
		var eblSolutionProvider *eblSolutionProvider
		for _, provider := range k.eblSolutionProviders {
			if provider.ManualKeyID == keyID {
				eblSolutionProvider = provider
				break
			}
		}

		// if no registry entry found, skip the key
		if eblSolutionProvider == nil {
			k.logger.Warn("skipping: kid not found in the platform registry - skipping",
				slog.String("file", filename),
				slog.String("kid", keyID))
			continue
		}

		k.logger.Info("public key loaded to keymanager ",
			slog.String("file", filename),
			slog.String("kid", keyID),
			slog.String("key_type", keyType))

		// Store key indexed by kid
		k.manualKeys[keyID] = &PublicKeyInfo{
			Provider: eblSolutionProvider,
			Key:      key,
			KeyID:    keyID,
		}

		k.logger.Debug("loaded manual key",
			slog.String("code", eblSolutionProvider.Code),
			slog.String("kid", keyID))
	}

	return nil
}

// initJWKCache initializes the JWK cache and registers all eBL solution provider JWK endpoints.
// The cache will automatically fetch and refresh JWK sets from each provider in the background.
func (k *KeyManager) initJWKCache(ctx context.Context) error {

	client := httprc.NewClient()

	cache, err := jwk.NewCache(ctx, client)
	if err != nil {
		return WrapKeyError(err, "failed to create JWK cache")
	}
	k.jwkCache = cache

	successCount := 0

	// Register each eBL solution provider's JWK endpoint
	for _, provider := range k.eblSolutionProviders {

		// check if the provider has a JWK endpoint configured
		if provider.JWKSEndpoint == "" {
			k.logger.Debug("no JWK endpoint configured for provider - skipping",
				slog.String("code", provider.Code))
			continue
		}

		err := k.jwkCache.Register(ctx, provider.JWKSEndpoint,
			jwk.WithMinInterval(k.config.JWKCacheMinRefreshInterval),
			jwk.WithMaxInterval(k.config.JWKCacheMaxRefreshInterval),
			jwk.WithWaitReady(false), // Don't block startup - fetch in background
		)
		if err != nil {
			k.logger.Warn("failed to register JWK endpoint",
				slog.String("code", provider.Code),
				slog.String("jwk_url", provider.JWKSEndpoint),
				slog.String("error", err.Error()))
			continue
		}

		successCount++
		k.logger.Info("registered JWK endpoint for background fetch",
			slog.String("code", provider.Code),
			slog.String("jwk_url", provider.JWKSEndpoint))
	}

	k.logger.Info("JWK cache initialization complete - keys will be fetched in background",
		slog.Int("endpoints_registered", successCount))

	return nil
}

// FetchKeys implements the jws.KeyProvider interface for automatic key lookup during JWS verification.
//
// It works like this:
//  1. The caller invokes jws.Verify() with jws.WithKeyProvider(keyManager)
//  2. The jws library passes the signature and message to this FetchKeys() method
//  3. We look up the key based on the KID and add it to the key sink
//  4. The key sink is used by the jws library to verify the signature.
//
// This eliminates the need for manual KID extraction as a separate step
// and allows us to check both the manual keys and the remote keys in a single location.
func (k *KeyManager) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
	kid, ok := sig.ProtectedHeaders().KeyID()
	if !ok || kid == "" {
		return NewValidationError("kid is required in JWS header")
	}

	alg, ok := sig.ProtectedHeaders().Algorithm()
	if !ok {
		return NewValidationError("alg is required in JWS header")
	}

	// 1. Check manual keys first
	k.mu.RLock()
	if keyInfo, exists := k.manualKeys[kid]; exists {
		k.mu.RUnlock()
		sink.Key(alg, keyInfo.Key)
		return nil
	}
	k.mu.RUnlock()

	// 2. Check remote keys from jwkCache
	if k.jwkCache != nil {
		for _, provider := range k.eblSolutionProviders {
			if provider.JWKSEndpoint == "" {
				continue
			}

			// Get latest keyset from cache (auto-refreshed by jwx library)
			keySet, err := k.jwkCache.Lookup(ctx, provider.JWKSEndpoint)
			if err != nil {
				k.logger.Debug("failed to lookup JWK set from cache",
					slog.String("code", provider.Code),
					slog.String("jwk_url", provider.JWKSEndpoint),
					slog.String("error", err.Error()))
				continue
			}

			// Find key by kid
			key, found := keySet.LookupKeyID(kid)
			if found {
				k.logger.Debug("found remote key",
					slog.String("kid", kid),
					slog.String("provider", provider.Code))

				sink.Key(alg, key)
				return nil
			}
		}
	}

	return NewKeyError(fmt.Sprintf("key not found: %s", kid))
}

// GetKey retrieves a public key by kid.
// This is a convenience method for non-JWS use cases that need access to key metadata.
//
// For JWS verification, you will typically want to use FetchKeys (jws.KeyProvider interface) instead
func (k *KeyManager) GetKey(ctx context.Context, keyID string) (*PublicKeyInfo, error) {
	if keyID == "" {
		return nil, NewInternalError("kid is required")
	}

	// Check manual keys first
	k.mu.RLock()
	if keyInfo, exists := k.manualKeys[keyID]; exists {
		k.mu.RUnlock()
		return keyInfo, nil
	}
	k.mu.RUnlock()

	// For remote keys, check jwkCache to get the latest version
	if k.jwkCache != nil {
		for _, provider := range k.eblSolutionProviders {
			if provider.JWKSEndpoint == "" {
				continue
			}

			keySet, err := k.jwkCache.Lookup(ctx, provider.JWKSEndpoint)
			if err != nil {
				continue
			}

			key, found := keySet.LookupKeyID(keyID)
			if found {
				// Return key info with metadata
				keyInfo := &PublicKeyInfo{
					Provider: provider,
					Key:      key,
					KeyID:    keyID,
				}

				k.logger.Debug("found remote key",
					slog.String("kid", keyID),
					slog.String("provider", provider.Code))

				return keyInfo, nil
			}
		}
	}

	return nil, NewKeyError(fmt.Sprintf("key not found: %s", keyID))
}

// LookupPlatformByKeyID returns the platform code that owns the given key ID.
// This implements the ebl.KeyLookupPlatformByKeyID interface
//
// Returns an error if the key is not found in the registry.
func (k *KeyManager) LookupPlatformByKeyID(ctx context.Context, keyID string) (string, error) {
	keyInfo, err := k.GetKey(ctx, keyID)
	if err != nil {
		return "", err
	}

	return keyInfo.Provider.Code, nil
}
