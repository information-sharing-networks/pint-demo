//go:build integration

package integration

// Test environment setup and server lifecycle management.
//
// The integration tests start the pint-server HTTP server with a temporary database and run tests against it.
// Each test creates an empty temporary database and applies all the migrations so the schema reflects the latest code.
// The database is dropped after each test.
//
// By default the server logs are not included in the test output, you can enable them with:
//
//	ENABLE_SERVER_LOGS=true go test -tags=integration -v ./test/integration

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

// Test configuration constants
const (
	testDatabaseName = "tmp_pint_integration_test"

	// CI database configuration
	ciPostgresDatabaseURL = "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"
	ciTestDatabaseURL     = "postgres://postgres:postgres@localhost:5432/" + testDatabaseName + "?sslmode=disable"

	// Local development database configuration
	localPostgresDatabaseURL = "postgres://pint-dev@localhost:15433/postgres?sslmode=disable"
	localTestDatabaseURL     = "postgres://pint-dev@localhost:15433/" + testDatabaseName + "?sslmode=disable"
)

// getTestDatabaseURL returns the appropriate test database URL for the local docker db when running locally
// or the CI test database when being run in github action
func getTestDatabaseURL() string {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		return ciTestDatabaseURL
	}
	return localTestDatabaseURL
}

// setupTestDatabase sets up a test database environment:
// - In CI: uses GitHub Actions PostgreSQL service
// - Locally: uses Docker Compose PostgreSQL container
// - applies database migrations and drops database on exit
func setupTestDatabase(t *testing.T, ctx context.Context) *pgxpool.Pool {
	// Check if we're in CI environment
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		return setupCIDatabase(t, ctx)
	}

	// local dev env
	return setupLocalDatabase(t, ctx)
}

// setupCIDatabase uses GitHub Actions PostgreSQL service
func setupCIDatabase(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Log("Running integration tests in CI")

	// Check PostgreSQL server connectivity
	postgresDatabase := setupDatabaseConn(t, ciPostgresDatabaseURL)
	if err := postgresDatabase.Ping(ctx); err != nil {
		t.Fatalf("❌ Can't ping PostgreSQL server %s", ciPostgresDatabaseURL)
	}

	// create the test database
	t.Logf("setting up test database %v", ciTestDatabaseURL)
	createTestDatabase(t, ctx, postgresDatabase, testDatabaseName)

	testDatabase := setupDatabaseConn(t, ciTestDatabaseURL)

	t.Log("test database created")

	// Apply database migrations
	if err := runDatabaseMigrations(t, testDatabase); err != nil {
		t.Fatalf("❌ Failed to apply database migrations: %v", err)
	}

	t.Log("✅ Database created")

	return testDatabase
}

// setupLocalDatabase uses Docker Compose database
func setupLocalDatabase(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Log("Running local integration test")

	// Check PostgreSQL server connectivity
	postgresDatabase := setupDatabaseConn(t, localPostgresDatabaseURL)
	if err := postgresDatabase.Ping(ctx); err != nil {
		t.Fatalf("❌ Can't ping PostgreSQL server %s - is the docker db container running? Run: docker compose up db", localPostgresDatabaseURL)
	}

	// create the test database
	t.Logf("setting up test database %v", localTestDatabaseURL)
	createTestDatabase(t, ctx, postgresDatabase, testDatabaseName)

	testDatabase := setupDatabaseConn(t, localTestDatabaseURL)

	// Apply database migrations
	if err := runDatabaseMigrations(t, testDatabase); err != nil {
		t.Fatalf("❌ Failed to apply database migrations: %v", err)
	}

	t.Log("✅ Database created")

	return testDatabase
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

func createTestDatabase(t *testing.T, ctx context.Context, pool *pgxpool.Pool, databaseName string) {
	t.Helper()

	// try to drop db in case previous run was killed and the test db still exists
	_, err := pool.Exec(ctx, "DROP DATABASE IF EXISTS "+databaseName)
	if err != nil {
		t.Fatalf("DROP DATABASE IF EXISTS Failed : %v", err)
	}

	_, err = pool.Exec(ctx, "CREATE DATABASE "+databaseName)
	if err != nil {
		t.Fatalf("CREATE DATABASE Failed : %v", err)
	}

	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DROP DATABASE "+databaseName)
		if err != nil {
			t.Fatalf("Failed to drop test database: %v", err)
		}
	})

	t.Log("Test database created")
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
	// Paths are relative to app/test/integration/ directory
	testEnvVars := map[string]string{
		"DATABASE_URL":          testDatabaseURL,
		"ENVIRONMENT":           "test",
		"LOG_LEVEL":             "debug",
		"PORT":                  fmt.Sprintf("%d", port),
		"HOST":                  "localhost",
		"REGISTRY_PATH":         "../../internal/crypto/testdata/platform-registry/eblsolutionproviders.csv",
		"MANUAL_KEYS_DIR":       "../../internal/crypto/testdata/keys",
		"SIGNING_KEY_PATH":      "../../internal/crypto/testdata/keys/ed25519-eblplatform.example.com.private.jwk",
		"X5C_CERT_PATH":         "../../internal/crypto/testdata/certs/ed25519-eblplatform.example.com-fullchain.crt",
		"X5C_CUSTOM_ROOTS_PATH": "../../internal/crypto/testdata/certs/root-ca.crt",
		"PLATFORM_CODE":         "EBL1",
		"SKIP_JWK_CACHE":        "true",
		"RATE_LIMIT_RPS":        "0", // disable rate limiting in tests
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
