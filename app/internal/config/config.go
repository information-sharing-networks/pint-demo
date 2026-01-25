package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Netflix/go-env"
)

// Environment variables with defaults
type ServerEnvironment struct {
	Environment        string        `env:"ENVIRONMENT,default=dev"`
	Host               string        `env:"HOST,default=0.0.0.0"`
	Port               int           `env:"PORT,default=8080"`
	PublicBaseURL      string        `env:"PUBLIC_BASE_URL"`
	SecretKey          string        `env:"SECRET_KEY,required=true"`
	LogLevel           string        `env:"LOG_LEVEL,default=debug"`
	DatabaseURL        string        `env:"DATABASE_URL,required=true"`
	ReadTimeout        time.Duration `env:"READ_TIMEOUT,default=15s"`
	WriteTimeout       time.Duration `env:"WRITE_TIMEOUT,default=15s"`
	IdleTimeout        time.Duration `env:"IDLE_TIMEOUT,default=60s"`
	AllowedOrigins     []string      `env:"ALLOWED_ORIGINS,separator=|"`
	RateLimitRPS       int32         `env:"RATE_LIMIT_RPS,default=100"`
	RateLimitBurst     int32         `env:"RATE_LIMIT_BURST,default=200"`
	DBMaxConnections   int32         `env:"DB_MAX_CONNECTIONS,default=4"`
	DBMinConnections   int32         `env:"DB_MIN_CONNECTIONS,default=0"`
	DBMaxConnLifetime  time.Duration `env:"DB_MAX_CONN_LIFETIME,default=60m"`
	DBMaxConnIdleTime  time.Duration `env:"DB_MAX_CONN_IDLE_TIME,default=30m"`
	DBConnectTimeout   time.Duration `env:"DB_CONNECT_TIMEOUT,default=5s"`
	PlatformID         string        `env:"PLATFORM_ID,default=DEMO_PLATFORM"`
	PlatformName       string        `env:"PLATFORM_NAME,default=Demo Platform"`
	DCSARegistryURL    string        `env:"DCSA_REGISTRY_URL,required=true"`
	MinTrustLevel      int           `env:"MIN_TRUST_LEVEL,default=2"`
	SkipJWKCache       bool          `env:"SKIP_JWK_CACHE,default=false"`
	JWKCacheMinRefresh time.Duration `env:"JWK_CACHE_MIN_REFRESH,default=10m"`
	JWKCacheMaxRefresh time.Duration `env:"JWK_CACHE_MAX_REFRESH,default=12h"`
}

const (
	// timeouts
	ServerShutdownTimeout = 10 * time.Second
	DatabasePingTimeout   = 10 * time.Second
	RegistryFetchTimeout  = 30 * time.Second // Timeout for fetching the registry of ebl solution providers
	JWKCacheHTTPTimeout   = 30 * time.Second // HTTP timeout for fetching JWK sets from remote endpoints
)

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

	// Default to host/port if not set
	if cfg.Environment != "prod" && cfg.Environment != "staging" && cfg.PublicBaseURL == "" {
		host := cfg.Host
		if host == "0.0.0.0" {
			host = "localhost"
		}
		cfg.PublicBaseURL = fmt.Sprintf("http://%s:%d", host, cfg.Port)
	}

	// Remove trailing slash from base url
	cfg.PublicBaseURL = strings.TrimSuffix(cfg.PublicBaseURL, "/")

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

	u, err := url.ParseRequestURI(cfg.PublicBaseURL)
	if err != nil {
		return fmt.Errorf("PUBLIC_BASE_URL is not a valid URL: %s", cfg.PublicBaseURL)
	}

	if u.Scheme == "" {
		return fmt.Errorf("PUBLIC_BASE_URL does not include a valid scheme (http or https): %s", cfg.PublicBaseURL)
	}

	if u.Hostname() == "" {
		return fmt.Errorf("PUBLIC_BASE_URL does not include a host: %s", cfg.PublicBaseURL)
	}

	// Default to all origins when not in prod/staging
	if len(cfg.AllowedOrigins) == 0 {
		cfg.AllowedOrigins = []string{"*"}
	}

	if cfg.MinTrustLevel < 1 || cfg.MinTrustLevel > 5 {
		return fmt.Errorf("MIN_TRUST_LEVEL must be between 1 and 5, got %d", cfg.MinTrustLevel)
	}

	return nil
}
