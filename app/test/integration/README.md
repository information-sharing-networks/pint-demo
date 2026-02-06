# Integration Tests

End-to-end tests that start the pint-server with a temporary database and test HTTP endpoints.

## Running Tests

```bash
# the tests require the docker db container to be running
# (the tests create a temporary database for testing)
docker compose up db -d

# Run all integration tests
cd app
go test -tags=integration ./test/integration/

# Run specific test
go test -tags=integration ./test/integration/ -run TestJWKS

# Enable server logs for debugging
ENABLE_SERVER_LOGS=true go test -tags=integration -v ./test/integration/
```

## Test Environment

- **Local**: Uses Docker Compose PostgreSQL on port `15433`
- **CI**: Uses GitHub Actions PostgreSQL on port `5432`
- Each test creates a temporary database with migrations applied
- Server runs on a random port to avoid conflicts
- Database and server are cleaned up after each test

## Test Data

Tests use resources from `app/internal/crypto/testdata/`:
- **Registry**: `platform-registry/eblsolutionproviders.csv`
- **Keys**: `keys/` directory (Ed25519 and RSA test keys)
- **Signing key**: `keys/ed25519-eblplatform.example.com.private.jwk` (platform code: EBL1)
- **Test json** (see `app/internal/crypto/testdata/README.md` for details)

