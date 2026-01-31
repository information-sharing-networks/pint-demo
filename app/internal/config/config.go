package config

import (
	"fmt"
	"time"

	"github.com/Netflix/go-env"
)

// Environment variables with defaults
//
// NOTE: When adding new environment variables, you must also add them to docker-compose.yml
// in the app service's environment section, otherwise they won't be passed to the container.
type ServerEnvironment struct {

	// http server settings
	Environment           string        `env:"ENVIRONMENT,default=dev"`
	Host                  string        `env:"HOST,default=0.0.0.0"`
	Port                  int           `env:"PORT,default=8080"`
	LogLevel              string        `env:"LOG_LEVEL,default=debug"`
	ServerShutdownTimeout time.Duration `env:"SERVER_SHUTDOWN_TIMEOUT,default=10s"`
	MinTrustLevel         int32         `env:"MIN_TRUST_LEVEL,default=1"`
	RegistryFetchTimeout  time.Duration `env:"REGISTRY_FETCH_TIMEOUT,default=10s"`
	MaxRequestSize        int64         `env:"MAX_REQUEST_SIZE,default=1048576"` // 1MB - limits request body size for all endpoints

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
	SigningKeyPath string `env:"SIGNING_KEY_PATH,required=true"`

	// DCSA issued 4 char platform code
	PlatformCode string `env:"PLATFORM_CODE,required=true"`

	// Path to X.509 certificate(s) in PEM format (optional)
	// When set, certificate(s) are included in the JWS x5c header for non-repudiation purposes
	// Can be a single leaf certificate or a full chain (leaf + intermediates)
	// The leaf certificate's public key must match the private key at SIGNING_KEY_PATH
	X5CCertPath string `env:"X5C_CERT_PATH"`

	// Path to custom root CA certificate(s) in PEM format (optional)
	// Use this when x5c certificates are issued by a private PKI
	// Leave unset to validate against system root CAs
	X5CCustomRootsPath string `env:"X5C_CUSTOM_ROOTS_PATH"`
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
		return fmt.Errorf("MIN_TRUST_LEVEL must be between 1 and 3, got %d", cfg.MinTrustLevel)
	}

	// TODO - this rule says participants using custom root CAs must also use x5c headers
	// (ie it is assumed the particpants in a private PKI require reciprical trust and must operate at trust-level 1 or 2)
	// .. but we don't have a similar rule for public CAs (allowing the particpants to select their trust level)
	// is this correct?
	if cfg.X5CCustomRootsPath != "" && cfg.X5CCertPath == "" {
		return fmt.Errorf("X5C_CUSTOM_ROOTS_PATH requires X5C_CERT_PATH: " +
			"platforms using custom root CAs must provide their own x5c certificate chain")
	}

	return nil
}
