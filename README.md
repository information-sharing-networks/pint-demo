# PINT Demo

A demonstration implementation of the DCSA PINT (Platform Interoperability) API v3.0.0 for electronic Bill of Lading (eBL) envelope transfers.

## Overview

This project implements both sender and receiver platforms for the PINT API, demonstrating:
- eBL envelope transfer workflow
- JWS digital signatures for non-repudiation
- SHA-256 checksum validation
- Additional document transfers
- Transfer chain tracking

## tech stack

- **Go 1.25.4** with modern patterns
- **Chi router** for HTTP routing
- **PostgreSQL** with pgx/v5 driver
- **SQLC** for type-safe database queries
- **Cobra** for CLI commands
- **JWS** signatures using go-jose

pint-demo/
├── app/
│   ├── cmd/
│   │   ├── pint-receiver/    # Receiver platform HTTP server
│   │   └── pint-sender/      # Sender platform CLI
│   ├── internal/
│   │   ├── cli/              # Sender CLI commands
│   │   ├── config/           # Configuration management
│   │   ├── logger/           # Structured logging
│   │   ├── server/           # HTTP server
│   │   └── database/         # SQLC generated code (gitignored)
│   ├── sql/
│   │   ├── schema/           # Database migrations
│   │   └── queries/          # SQLC queries
│   ├── go.mod
│   └── sqlc.yaml
├── docker-compose.yml
├── Makefile
```

## Getting Started

### Prerequisites

- Docker and Docker Compose (recommended)
- OR Go 1.25.4+ with PostgreSQL 17 for local development

### Quick Start (Docker - Recommended)

1. **Start the development environment**:
   ```bash
   docker compose up
   ```

   This will:
   - Start PostgreSQL 17
   - Generate SQLC code
   - Run database migrations
   - Start the pint-receiver service on http://localhost:8080

2. **Check the service is running**:
   ```bash
   curl http://localhost:8080/health
   ```

3. **Access the database**:
   ```bash
   make psql
   ```

4. **View logs**:
   ```bash
   make logs
   ```

If you prefer to run Go locally:

1. **Start PostgreSQL**:
   ```bash
   make docker-up  # Just starts the database
   ```

2. **Copy environment file**:
   ```bash
   cp .env.example .env
   ```

3. **Install Go tools** (if not using Docker):
   ```bash
   go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
   go install github.com/pressly/goose/v3/cmd/goose@latest
   ```

4. **Generate SQLC code and run migrations**:
   ```bash
   cd app
   sqlc generate
   export DATABASE_URL="postgres://pint-dev@localhost:15433/pint_demo?sslmode=disable"
   goose -dir sql/schema postgres "$DATABASE_URL" up
   ```

5. **Run the receiver**:
   ```bash
   make run-receiver
   ```

6. **Run the sender CLI**:
   ```bash
   make run-sender
   ```

#### Development Tools

All development tools are available via Docker (no local installation needed):

```bash
make sqlc      # Generate SQLC code
make migrate   # Run database migrations
make fmt       # Format code
make vet       # Run go vet
make test      # Run tests
make check     # Run all checks (fmt, vet, test)
```

## Project Status

### ✅ Phase 1: Foundation (Complete)
- Project structure with Go 1.25.4
- Chi router for HTTP routing
- PostgreSQL 17 database
- SQLC for type-safe queries
- Cobra CLI framework
- Database schema and migrations
- Basic HTTP server
- Docker Compose development environment

### 🚧 Phase 2: Cryptographic Operations (In Progress)
Skeleton code created for:
- RSA key generation and management (`app/internal/crypto/keys.go`)
- JWS signing and verification (`app/internal/crypto/jws.go`)
- SHA-256 checksum calculation (`app/internal/crypto/checksum.go`)
- JWK format conversion (`app/internal/crypto/jwk.go`)
- Hybrid public key distribution (`app/internal/crypto/keymanager.go`)
- JWK endpoint handler (`app/internal/server/jwks_handler.go`)

**Next:** Implement the TODO functions in the crypto package. See `notes/PHASE2_IMPLEMENTATION_GUIDE.md` for details.

### 📋 Phase 3: PINT API Handlers (Planned)
- Implement `/v3/envelopes` endpoint (start envelope transfer)
- Implement `/v3/envelopes/{ref}/additional-documents/{checksum}` endpoint
- Implement `/v3/envelopes/{ref}/finish-transfer` endpoint
- Implement `/v3/receiver-validation` endpoint
- Integrate crypto functions into handlers
- Connect sender CLI to PINT API

### 📋 Phase 4: Database Integration (Planned)
- Store envelope transfer history
- Cache fetched public keys
- Store envelope signatures for audit trail

### 📋 Phase 5: Testing & Demo (Planned)
- End-to-end transfer between sender and receiver
- Test signature verification
- Test checksum validation
- Demo the full PINT workflow
