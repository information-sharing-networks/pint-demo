//go:build integration

package integration

// Test environment setup and server lifecycle management.
//
// The integration tests start the pint-server HTTP server with a temporary database and run tests against it.
// Each test creates an empty temporary database and applies all the migrations so the schema reflects the latest code.
// The database is dropped after each test.
//
// the server starts as EBL2 platform (ie uses the EBL2 platform code and ebl2 private key)
// This is because EBL2 is the receiving platform of the test envelope used for transfer tests (HHL71800000-ebl-envelope-ed25519.json),
// see serverConfig for other settings
//
// By default the server logs are not included in the test output, you can enable them with:
//
//	ENABLE_SERVER_LOGS=true go test -tags=integration -v ./test/integration
//

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/information-sharing-networks/pint-demo/app/internal/config"
	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/information-sharing-networks/pint-demo/app/internal/database"
	"github.com/information-sharing-networks/pint-demo/app/internal/logger"
	"github.com/information-sharing-networks/pint-demo/app/internal/server"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// testEnv provides access to test db and server for integration tests
type testEnv struct {
	baseURL  string
	cfg      *config.ServerEnvironment
	pool     *pgxpool.Pool
	queries  *database.Queries
	shutdown func()
}

// startInProcessServer starts the pint-server in-process for testing - returns the base URL for the API and a shutdown function
// the signing key used is determined by the platformCode parameter (EBL1, EBL2 or CAR1 are supported)
func startInProcessServer(t *testing.T, platformCode string, minTrustLevel crypto.TrustLevel) *testEnv {
	t.Helper()

	testEnv := &testEnv{}

	t.Log("Starting in-process server...")
	t.Logf("platformCode: %s", platformCode)

	// server config
	var (
		ctx                 = context.Background()
		host                = "localhost"
		port                = findFreePort(t)
		skipJWKCache        = true
		rateLimitRPS        = 0
		enviornment         = "test"
		logLevel            = logger.ParseLogLevel("none")
		x5cCustomRootsPath  = "../testdata/certs/root-ca.crt"
		registryPath        = "../testdata/platform-registry/eblsolutionproviders.csv"
		manualKeysDir       = "../testdata/keys"
		signingKeyPath      string
		x5cCertPath         string
		partyServiceName    = "local"
		partyServiceBaseURL = "http://localhost" + fmt.Sprintf(":%d", port) + "/admin/parties"
	)

	switch platformCode {
	case "EBL1":
		signingKeyPath = "../testdata/keys/ed25519-eblplatform.example.com.private.jwk"
		x5cCertPath = "../testdata/certs/ed25519-eblplatform.example.com-fullchain.crt"
	case "EBL2":
		signingKeyPath = "../testdata/keys/rsa-eblplatform.example.com.private.jwk"
		x5cCertPath = "../testdata/certs/rsa-eblplatform.example.com-fullchain.crt"
	case "CAR1":
		signingKeyPath = "../testdata/keys/ed25519-carrier.example.com.private.jwk"
		x5cCertPath = "../testdata/certs/ed25519-carrier.example.com-fullchain.crt"
	default:
		t.Fatalf("platform code: %s not supported (use EBL1, EBL2 or CAR1)", platformCode)
	}

	// configure db
	testEnv.pool = setupTestDatabase(t)
	testDatabaseURL := testEnv.pool.Config().ConnString()

	// Set environment variables before calling NewServerConfig
	testEnvVars := map[string]string{
		"HOST":           host,
		"SKIP_JWK_CACHE": fmt.Sprintf("%v", skipJWKCache),
		"RATE_LIMIT_RPS": fmt.Sprintf("%d", rateLimitRPS),

		"DATABASE_URL": testDatabaseURL,
		"ENVIRONMENT":  enviornment,
		"LOG_LEVEL":    logLevel.String(),
		"PORT":         fmt.Sprintf("%d", port),

		"REGISTRY_PATH":          registryPath,
		"MANUAL_KEYS_DIR":        manualKeysDir,
		"SIGNING_KEY_PATH":       signingKeyPath,
		"X5C_CERT_PATH":          x5cCertPath,
		"X5C_CUSTOM_ROOTS_PATH":  x5cCustomRootsPath,
		"PLATFORM_CODE":          platformCode,
		"PARTY_SERVICE_NAME":     partyServiceName,
		"PARTY_SERVICE_BASE_URL": partyServiceBaseURL,
		"MIN_TRUST_LEVEL":        fmt.Sprintf("%d", minTrustLevel),
	}

	// Save original env vars and set test values
	originalEnvVars := make(map[string]string)
	for key, value := range testEnvVars {
		originalEnvVars[key] = os.Getenv(key)
		os.Setenv(key, value)
	}

	// Restore original environment variables when test completes
	t.Cleanup(func() {
		for key, original := range originalEnvVars {
			if original != "" {
				os.Setenv(key, original)
			} else {
				os.Unsetenv(key)
			}
		}
	})

	cfg, err := config.NewServerConfig()
	if err != nil {
		t.Fatalf("Failed to load configuration: %v", err)
	}

	testEnv.queries = database.New(testEnv.pool)

	logLevel = logger.ParseLogLevel("none")
	if os.Getenv("ENABLE_SERVER_LOGS") == "true" {
		logLevel = logger.ParseLogLevel("Info")
	}

	appLogger := logger.InitLogger(logLevel, "test")

	serverInstance, err := server.NewServer(
		testEnv.pool,
		testEnv.queries,
		cfg,
		appLogger,
		ctx,
	)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create a cancellable context for server shutdown
	serverCtx, serverCancel := context.WithCancel(ctx)

	// Start server
	serverDone := make(chan error, 1)
	go func() {
		defer close(serverDone)
		if err := serverInstance.Start(serverCtx); err != nil {
			serverDone <- err
		}
	}()

	// Create shutdown function to be called by the test
	testEnv.shutdown = func() {
		t.Log("Stopping server...")

		// Cancel the server context to trigger graceful shutdown
		serverCancel()

		// Wait for server to shut down gracefully with timeout
		select {
		case err := <-serverDone:
			if err != nil {
				t.Logf("❌ Server shutdown with error: %v", err)
			} else {
				t.Log("✅ Server shut down gracefully")
			}
		case <-time.After(5 * time.Second):
			t.Log("⚠️ Server shutdown timeout")
		}

		// Ensure database connections are closed
		serverInstance.DatabaseShutdown()
	}

	testEnv.baseURL = fmt.Sprintf("http://localhost:%d", port)
	t.Logf("Starting in-process server at %s", testEnv.baseURL)

	testEnv.cfg = cfg

	// Wait for server to be ready
	if !waitForServer(t, testEnv.baseURL+"/health/live", 30*time.Second) {
		t.Fatal("Server failed to start within timeout")
	}

	// Test the server is working
	resp, err := http.Get(testEnv.baseURL + "/health/live")
	if err != nil {
		t.Fatalf("Failed to call health endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	t.Log("✅ Server started")
	return testEnv
}

func findFreePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port
}

func waitForServer(t *testing.T, url string, timeout time.Duration) bool {
	t.Helper()

	client := &http.Client{Timeout: 1 * time.Second}
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// Test database configuration

type databaseConfig struct {
	user   string // user[:password]
	dbname string
	host   string
	port   int
}

func (d *databaseConfig) connectionURL() string {
	return fmt.Sprintf("postgres://%s@%s:%d/%s?sslmode=disable",
		d.user, d.host, d.port, d.dbname)
}

func (d *databaseConfig) WithDbname(dbname string) *databaseConfig {
	return &databaseConfig{
		user:   d.user,
		host:   d.host,
		port:   d.port,
		dbname: dbname,
	}
}

func (d *databaseConfig) WithPort(port int) *databaseConfig {
	return &databaseConfig{
		user:   d.user,
		host:   d.host,
		port:   port,
		dbname: d.dbname,
	}
}

func (d *databaseConfig) WithUser(user string) *databaseConfig {
	return &databaseConfig{
		user:   user,
		host:   d.host,
		port:   d.port,
		dbname: d.dbname,
	}
}

// setupTestDatabase creates an empty test db, applies migrations and returns a connection pool
// the function auto-detetcs if it is running in CI (github actions) and uses the appropriate database config
func setupTestDatabase(t *testing.T) *pgxpool.Pool {
	ctx := context.Background()
	config := &databaseConfig{
		host: "localhost",
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		config = config.WithUser("postgres:postgres").
			WithPort(5432)
	} else {
		config = config.WithUser("pint-dev").
			WithPort(15433)
	}

	// Generate a unique test database name
	testDbName := fmt.Sprintf("test_%d", time.Now().UnixMilli())

	// Connect to the postgres database to create the test database
	postgresConfig := config.WithDbname("postgres")
	postgresConnectionURL := postgresConfig.connectionURL()

	postgresPoolConfig, err := pgxpool.ParseConfig(postgresConnectionURL)
	if err != nil {
		t.Fatalf("Failed to parse postgres database URL: %v", err)
	}
	postgresPool, err := pgxpool.NewWithConfig(ctx, postgresPoolConfig)
	if err != nil {
		t.Fatalf("Unable to create postgres connection pool: %v", err)
	}
	if err := postgresPool.Ping(ctx); err != nil {
		t.Fatalf("Can't ping PostgreSQL server %s", postgresConnectionURL)
	}

	_, err = postgresPool.Exec(ctx, "CREATE DATABASE "+testDbName)
	if err != nil {
		t.Fatalf("CREATE DATABASE failed: %v", err)
	}
	t.Logf("Created database: %s", testDbName)

	t.Cleanup(func() {
		postgresPool.Close()
	})

	t.Cleanup(func() {
		_, err := postgresPool.Exec(ctx, "DROP DATABASE "+testDbName+" WITH (FORCE)")
		if err != nil {
			t.Fatalf("Failed to drop test database: %v", err)
		}
		t.Logf("Dropped database: %s", testDbName)
	})

	// Connect to the new test database
	testDbConfig := config.WithDbname(testDbName)
	testDatabaseURL := testDbConfig.connectionURL()
	testDatabasePool := setupDatabaseConn(t, testDatabaseURL)

	// Apply database migrations
	if err := runDatabaseMigrations(t, testDatabasePool); err != nil {
		t.Fatalf("Failed to apply database migrations: %v", err)
	}
	t.Logf("Database ready: %s", testDbName)

	return testDatabasePool
}

func setupDatabaseConn(t *testing.T, databaseURL string) *pgxpool.Pool {
	t.Helper()

	ctx := context.Background()
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("Failed to parse database URL: %v", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("Unable to create connection pool: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
	})

	return pool
}

// runDatabaseMigrations applies all pending Goose migrations to the test database
func runDatabaseMigrations(t *testing.T, pool *pgxpool.Pool) error {
	t.Helper()

	// Convert pgx pool to database/sql interface that Goose expects
	var db *sql.DB = stdlib.OpenDBFromPool(pool)
	defer db.Close()

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set goose dialect: %w", err)
	}

	// Apply migrations from the sql/schema directory
	migrationDir := "../../sql/schema"
	if err := goose.Up(db, migrationDir); err != nil {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	return nil
}
