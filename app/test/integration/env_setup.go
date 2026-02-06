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
	"github.com/information-sharing-networks/pint-demo/app/internal/database"
	"github.com/information-sharing-networks/pint-demo/app/internal/logger"
	"github.com/information-sharing-networks/pint-demo/app/internal/server"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// testEnvironment holds common test dependencies
type testEnvironment struct {
	dbConn  *pgxpool.Pool
	queries *database.Queries
}

// setupTestEnvironment creates a new test environment with database connection and services
func setupTestEnvironment(dbConn *pgxpool.Pool) *testEnvironment {
	return &testEnvironment{
		dbConn:  dbConn,
		queries: database.New(dbConn),
	}
}

// cleanupDatabase truncates the envelope tables to reset the database state between tests
func cleanupDatabase(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()

	_, err := pool.Exec(ctx, `
		TRUNCATE TABLE transport_documents CASCADE;
	`)
	if err != nil {
		t.Fatalf("Failed to cleanup database: %v", err)
	}
}

// Test configuration

type databaseConfig struct {
	userAndPassword string
	password        string
	dbname          string
	host            string
	port            int
}

// serverConfig holds PINT server configuration for tests
// All paths are relative to app/test/integration/ directory
type serverConfig struct {
	environment        string
	logLevel           string
	registryPath       string
	manualKeysDir      string
	signingKeyPath     string
	x5cCertPath        string
	x5cCustomRootsPath string
	platformCode       string
}

var (
	ciDatabaseConfig = databaseConfig{
		userAndPassword: "postgres:postgres",
		dbname:          "tmp_pint_integration_test",
		host:            "localhost",
		port:            5432,
	}
	localDatabaseConfig = databaseConfig{
		userAndPassword: "pint-dev",
		dbname:          "tmp_pint_integration_test",
		host:            "localhost",
		port:            15433,
	}

	testServerConfig = serverConfig{
		environment:        "test",
		logLevel:           "debug",
		registryPath:       "../../internal/crypto/testdata/platform-registry/eblsolutionproviders.csv",
		manualKeysDir:      "../../internal/crypto/testdata/keys",
		signingKeyPath:     "../../internal/crypto/testdata/keys/ed25519-eblplatform.example.com.private.jwk",
		x5cCertPath:        "../../internal/crypto/testdata/certs/ed25519-eblplatform.example.com-fullchain.crt",
		x5cCustomRootsPath: "../../internal/crypto/testdata/certs/root-ca.crt",
		platformCode:       "EBL2", // this is the receiving platform of the test envelope (HHL71800000-ebl-envelope-ed25519.json)
	}
)

func buildConnString(userAndPassword string, host string, port int, dbname string) string {
	return fmt.Sprintf("postgres://%s@%s:%d/%s?sslmode=disable",
		userAndPassword, host, port, dbname)
}

// getDatabaseURL returns the appropriate test database URL for the local docker db when running locally
// or the CI test database when being run in github action
func getDatabaseURL() string {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		return buildConnString(ciDatabaseConfig.userAndPassword, ciDatabaseConfig.host, ciDatabaseConfig.port, ciDatabaseConfig.dbname)
	}
	return buildConnString(localDatabaseConfig.userAndPassword, localDatabaseConfig.host, localDatabaseConfig.port, localDatabaseConfig.dbname)
}

// setupCleanDatabase creates an empty test db, applies migrations and returns a connection pool
func setupCleanDatabase(t *testing.T, ctx context.Context) *pgxpool.Pool {

	config := localDatabaseConfig

	if os.Getenv("GITHUB_ACTIONS") == "true" {
		config = ciDatabaseConfig
		t.Log("Running integration tests in CI")
	}

	// connect to the postgres database to create the test database
	postgresConnectionURL := buildConnString(config.userAndPassword, config.host, config.port, "postgres")

	// Check PostgreSQL server connectivity
	postgresPool := setupDatabaseConn(t, postgresConnectionURL)
	if err := postgresPool.Ping(ctx); err != nil {
		t.Fatalf("❌ Can't ping PostgreSQL server %s", postgresConnectionURL)
	}

	_, err := postgresPool.Exec(ctx, "DROP DATABASE IF EXISTS "+config.dbname)
	if err != nil {
		t.Fatalf("DROP DATABASE IF EXISTS Failed : %v", err)
	}

	_, err = postgresPool.Exec(ctx, "CREATE DATABASE "+config.dbname)
	if err != nil {
		t.Fatalf("CREATE DATABASE Failed : %v", err)
	}

	// drop the test database when the test is complete
	t.Cleanup(func() {
		_, err := postgresPool.Exec(ctx, "DROP DATABASE "+config.dbname)
		if err != nil {
			t.Fatalf("Failed to drop test database: %v", err)
		}
	})
	t.Log("test database created")

	testDatabaseURLTODO := buildConnString(config.userAndPassword, config.host, config.port, config.dbname)
	testDatabasePool := setupDatabaseConn(t, testDatabaseURLTODO)

	// Apply database migrations
	if err := runDatabaseMigrations(t, testDatabasePool); err != nil {
		t.Fatalf("❌ Failed to apply database migrations: %v", err)
	}
	// Convert pgx pool to database/sql interface that Goose expects
	var db *sql.DB = stdlib.OpenDBFromPool(testDatabasePool)
	defer db.Close()

	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("failed to set goose dialect: %v", err)
	}

	// Apply migrations from the sql/schema directory
	migrationDir := "../../sql/schema"
	if err := goose.Up(db, migrationDir); err != nil {
		t.Fatalf("failed to apply migrations: %v", err)
	}

	t.Log("✅ Database created")

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

	t.Log("Database pool created")
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

// startInProcessServer starts the pint-server in-process for testing - returns the base URL for the API and a shutdown function
func startInProcessServer(t *testing.T, ctx context.Context, testDB *pgxpool.Pool, testDatabaseURL string) (string, func()) {
	t.Helper()

	enableServerLogs := false

	if os.Getenv("ENABLE_SERVER_LOGS") == "true" {
		enableServerLogs = true
	}

	// Find a free port for the test server
	port := findFreePort(t)

	// Set environment variables before calling NewServerConfig
	testEnvVars := map[string]string{
		"HOST":           "localhost",
		"SKIP_JWK_CACHE": "true",
		"RATE_LIMIT_RPS": "0",

		"DATABASE_URL": testDatabaseURL,
		"ENVIRONMENT":  testServerConfig.environment,
		"LOG_LEVEL":    testServerConfig.logLevel,
		"PORT":         fmt.Sprintf("%d", port),

		"REGISTRY_PATH":         testServerConfig.registryPath,
		"MANUAL_KEYS_DIR":       testServerConfig.manualKeysDir,
		"SIGNING_KEY_PATH":      testServerConfig.signingKeyPath,
		"X5C_CERT_PATH":         testServerConfig.x5cCertPath,
		"X5C_CUSTOM_ROOTS_PATH": testServerConfig.x5cCustomRootsPath,
		"PLATFORM_CODE":         testServerConfig.platformCode,
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

	queries := database.New(testDB)

	logLevel := logger.ParseLogLevel("none")
	if enableServerLogs {
		logLevel = logger.ParseLogLevel("debug")
	}
	appLogger := logger.InitLogger(logLevel, "test")

	serverInstance, err := server.NewServer(
		testDB,
		queries,
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
	shutdownFunc := func() {
		t.Log("Stopping server...")

		// Cancel the server context to trigger graceful shutdown
		serverCancel()

		// Wait for server to shut down gracefully with timeout
		select {
		case err := <-serverDone:
			if err != nil {
				t.Logf("Server shutdown with error: %v", err)
			} else {
				t.Log("✅ Server shut down gracefully")
			}
		case <-time.After(5 * time.Second):
			t.Log("⚠️ Server shutdown timeout")
		}

		// Ensure database connections are closed
		serverInstance.DatabaseShutdown()
	}

	baseURL := fmt.Sprintf("http://localhost:%d", port)
	t.Logf("Starting in-process server at %s", baseURL)

	// Wait for server to be ready
	if !waitForServer(t, baseURL+"/health/live", 30*time.Second) {
		t.Fatal("Server failed to start within timeout")
	}

	// Test the server is working
	resp, err := http.Get(baseURL + "/health/live")
	if err != nil {
		t.Fatalf("Failed to call health endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	return baseURL, shutdownFunc
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
