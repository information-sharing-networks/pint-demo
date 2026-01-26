package config

import (
	"fmt"
	"time"

	"github.com/Netflix/go-env"
)

// Environment variables with defaults
type ServerEnvironment struct {

	// http server settings
	Environment           string        `env:"ENVIRONMENT,default=dev"`
	Host                  string        `env:"HOST,default=0.0.0.0"`
	Port                  int           `env:"PORT,default=8080"`
	LogLevel              string        `env:"LOG_LEVEL,default=debug"`
	ServerShutdownTimeout time.Duration `env:"SERVER_SHUTDOWN_TIMEOUT,default=10s"`
	MinTrustLevel         int           `env:"MIN_TRUST_LEVEL,default=1"`
	RegistryFetchTimeout  time.Duration `env:"REGISTRY_FETCH_TIMEOUT,default=10s"`

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

	// Required PINT configuration - must be set by environment variables
	RegistryPath   string `env:"REGISTRY_PATH,required=true"`
	ManualKeysDir  string `env:"MANUAL_KEYS_DIR,required=true"`
	SigningKeyPath string `env:"SIGNING_KEY_PATH,required=true"`
	PlatformCode   string `env:"PLATFORM_CODE,required=true"`
	DatabaseURL    string `env:"DATABASE_URL,required=true"`
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

	return nil
}
