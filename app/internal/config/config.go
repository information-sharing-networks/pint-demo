// config provides the configuration for the PINT server and CLI.
// The configuration is loaded from environment variables and sensible defaults.
package config

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Netflix/go-env"
	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

// Environment variables with defaults
//
// NOTE: When adding new environment variables, you must also add them to docker-compose.yml
// in the app service's environment section, otherwise they won't be passed to the container.
type ServerEnvironment struct {

	// http server settings
	Environment           string            `env:"ENVIRONMENT,default=dev"`
	Host                  string            `env:"HOST,default=0.0.0.0"`
	Port                  int               `env:"PORT,default=8080"`
	LogLevel              string            `env:"LOG_LEVEL,default=debug"`
	ServerShutdownTimeout time.Duration     `env:"SERVER_SHUTDOWN_TIMEOUT,default=10s"`
	MinTrustLevel         crypto.TrustLevel `env:"MIN_TRUST_LEVEL,default=3"` // Default to highest trust (EV/OV)
	RegistryFetchTimeout  time.Duration     `env:"REGISTRY_FETCH_TIMEOUT,default=10s"`
	MaxRequestSize        int64             `env:"MAX_REQUEST_SIZE,default=1048576"` // 1MB - limits request body size for all endpoints

	// database settings
	ReadTimeout         time.Duration `env:"READ_TIMEOUT,default=15s"`
	WriteTimeout        time.Duration `env:"WRITE_TIMEOUT,default=15s"`
	IdleTimeout         time.Duration `env:"IDLE_TIMEOUT,default=60s"`
	AllowedOrigins      []string      `env:"ALLOWED_ORIGINS,separator=|"`
	RateLimitRPS        int32         `env:"RATE_LIMIT_RPS,default=100"`
	RateLimitBurst      int32         `env:"RATE_LIMIT_BURST,default=200"`
	DBMaxConnections    int32         `env:"DB_MAX_CONNECTIONS,default=4"`
	DBMinConnections    int32         `env:"DB_MIN_CONNECTIONS,default=0"`
	DBMaxConnLifetime   time.Duration `env:"DB_MAX_CONN_LIFETIME,default=60m"`
	DBMaxConnIdleTime   time.Duration `env:"DB_MAX_CONN_IDLE_TIME,default=30m"`
	DBConnectTimeout    time.Duration `env:"DB_CONNECT_TIMEOUT,default=5s"`
	DatabasePingTimeout time.Duration `env:"DATABASE_PING_TIMEOUT,default=10s"`

	// JWK cache settings
	SkipJWKCache        bool          `env:"SKIP_JWK_CACHE,default=false"`
	JWKCacheMinRefresh  time.Duration `env:"JWK_CACHE_MIN_REFRESH,default=10m"`
	JWKCacheMaxRefresh  time.Duration `env:"JWK_CACHE_MAX_REFRESH,default=12h"`
	JWKCacheHTTPTimeout time.Duration `env:"JWK_CACHE_HTTP_TIMEOUT,default=30s"`

	// **Required configuration - the following environment variables and must be set at start up**

	DatabaseURL string `env:"DATABASE_URL,required=true"`

	// Path to CSV file containing the registry of all approved eBL PINT participants
	RegistryPath string `env:"REGISTRY_PATH,required=true"`

	// The keymanager will load any public key in this directory that has a matching kid in the registry
	// other keys will be ignored.
	// Supported file extensions: .jwk, .jwks, .jwks.json
	// The keymanager expects one key per file.
	ManualKeysDir string `env:"MANUAL_KEYS_DIR,required=true"`

	// Path to the private JWK file used to sign eBL documents - Ed25519 or RSA keys are supported
	// In prod/staging, this should point to a mounted secret (e.g., /run/secrets/signing-key.jwk)
	SigningKeyPath string `env:"SIGNING_KEY_PATH,required=true"`

	// DCSA issued 4 char platform code
	PlatformCode string `env:"PLATFORM_CODE,required=true"`

	// Path to X.509 certificate(s) in PEM format (optional)
	// When set, certificate(s) are included in the JWS x5c header for non-repudiation purposes
	// Can be a single leaf certificate or a full chain (leaf + intermediates)
	// The leaf certificate's public key must match the private key at SIGNING_KEY_PATH
	// In prod/staging, this should point to a mounted secret (e.g., /run/secrets/cert-chain.pem)
	X5CCertPath string `env:"X5C_CERT_PATH"`

	// Path to custom root CA certificate(s) in PEM format (optional)
	// Use this when x5c certificates are issued by a private PKI
	// Leave unset to validate against system root CAs
	// In prod/staging, this should point to a mounted config (e.g., /etc/pint/custom-roots.pem)
	X5CCustomRootsPath string `env:"X5C_CUSTOM_ROOTS_PATH"`

	// PartyServiceName selects which party validation implementation to use
	//
	// See app/internal/services/party_validator.go for implementation details
	PartyServiceName string `env:"PARTY_SERVICE_NAME,default=local"`

	// PartyServiceBaseURL is the base URL of the party management service
	PartyServiceBaseURL string `env:"PARTY_SERVICE_BASE_URL,required=true"`
}

var validEnvs = map[string]bool{
	"dev":     true,
	"test":    true,
	"prod":    true,
	"staging": true,
}

// NewServerConfig loads environment variables and returns a ServerEnvironment struct that contains the values
func NewServerConfig() (*ServerEnvironment, error) {
	var cfg ServerEnvironment

	_, err := env.UnmarshalFromEnviron(&cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal environment variables: %w", err)
	}

	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil

}

// validateConfig checks for required env variables
func validateConfig(cfg *ServerEnvironment) error {
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("PORT must be between 1 and 65535")
	}
	if !validEnvs[cfg.Environment] {
		return fmt.Errorf("invalid ENVIRONMENT: %s", cfg.Environment)
	}

	// Validate database pool configuration
	if cfg.DBMaxConnections < 1 {
		return fmt.Errorf("DB_MAX_CONNECTIONS must be at least 1")
	}
	if cfg.DBMinConnections < 0 {
		return fmt.Errorf("DB_MIN_CONNECTIONS must be 0 or greater")
	}
	if cfg.DBMinConnections > cfg.DBMaxConnections {
		return fmt.Errorf("DB_MIN_CONNECTIONS (%d) cannot be greater than DB_MAX_CONNECTIONS (%d)",
			cfg.DBMinConnections, cfg.DBMaxConnections)
	}

	if cfg.MinTrustLevel < 1 || cfg.MinTrustLevel > 3 {
		return fmt.Errorf("MIN_TRUST_LEVEL must be between 1 and 3 (1=NoX5C, 2=DV, 3=EV/OV), got %d", cfg.MinTrustLevel)
	}

	// In prod/staging, validate that secret paths point to approved mount locations
	if cfg.Environment == "prod" || cfg.Environment == "staging" {
		if err := validateSecretPath(cfg.SigningKeyPath, "SIGNING_KEY_PATH"); err != nil {
			return err
		}
		if cfg.X5CCertPath != "" {
			if err := validateSecretPath(cfg.X5CCertPath, "X5C_CERT_PATH"); err != nil {
				return err
			}
		}
		if cfg.X5CCustomRootsPath != "" {
			if err := validateConfigPath(cfg.X5CCustomRootsPath, "X5C_CUSTOM_ROOTS_PATH"); err != nil {
				return err
			}
		}
	}

	// TODO - this rule says participants using custom root CAs must also use x5c headers
	// (ie it is assumed the particpants in a private PKI require reciprical trust and must operate at trust-level 2 or 3)
	// .. but we don't have a similar rule for public CAs (allowing the particpants to select their trust level)
	// is this correct?
	if cfg.X5CCustomRootsPath != "" && cfg.X5CCertPath == "" {
		return fmt.Errorf("X5C_CUSTOM_ROOTS_PATH requires X5C_CERT_PATH: " +
			"platforms using custom root CAs must provide their own x5c certificate chain")
	}

	// Validate platform code exists in registry
	if err := validatePlatformCodeInRegistry(cfg); err != nil {
		return err
	}

	return nil
}

// validateSecretPath ensures that in prod/staging, secret file paths point to approved mount locations.
func validateSecretPath(path, envVarName string) error {
	// Approved mount points for secrets in production
	approvedPrefixes := []string{
		"/run/secrets/",
		"/var/run/secrets/",
		"/secrets/",
	}

	for _, prefix := range approvedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return nil
		}
	}

	return fmt.Errorf("%s must point to a mounted secret location in prod/staging (e.g., /run/secrets/*, /secrets/*), got: %s", envVarName, path)
}

func validateConfigPath(path, envVarName string) error {
	// Approved mount points for config files in production
	approvedPrefixes := []string{
		"/etc/",
		"/config/",
	}

	for _, prefix := range approvedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return nil
		}
	}

	return fmt.Errorf("%s must point to a mounted config location in prod/staging (e.g., /etc/*, /config/*), got: %s", envVarName, path)
}

// validatePlatformCodeInRegistry validates that the configured platform code exists in the registry.
//
// IMPORTANT: This check only validates registry membership, not key ownership.
// Platform impersonation is prevented at runtime - see detailed note below.
//
// If a registered platform starts up with the wrong platform code
// this will not be caught at startup. However, the misconfiguration will prevent transfers:
//
// **Sending transfers**
// The receiving platform extracts the kid from the JWS signature, looks up which platform
// owns that key in the registry (via KeyManager), and compares it to the eblPlatform field
// in the last transfer chain entry. If they don't match, the transfer is rejected.
// This prevents a platform from signing with their own key while claiming the
// transfer is from a different platform.
//
// **Receiving transfers**
// The misconfigured platform can validate signatures and chain integrity normally.
// However, if the sender addressed the transfer to the correct platform code (not the
// misconfigured one), the transfer will fail because the intended recipient
// won't match the server's configured platform code. This prevents a platform from
// processing transfers that are not addressed to it.
//
// Both checks are performed in ebl.VerifyEnvelopeTransfer.
func validatePlatformCodeInRegistry(cfg *ServerEnvironment) error {
	// Load the registry
	data, err := os.ReadFile(cfg.RegistryPath)
	if err != nil {
		return fmt.Errorf("failed to read registry file: %w", err)
	}

	// Parse the CSV
	reader := csv.NewReader(bytes.NewReader(data))
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to parse registry CSV: %w", err)
	}

	// Check if platform code exists in registry
	for _, record := range records[:] {
		if len(record) > 0 && record[0] == cfg.PlatformCode {
			return nil
		}
	}

	return fmt.Errorf("PLATFORM_CODE %s not found in registry at %s", cfg.PlatformCode, cfg.RegistryPath)
}
