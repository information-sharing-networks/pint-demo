# PINT Demo

A demonstration implementation of the DCSA PINT (Platform Interoperability) API v3.0.0 for electronic Bill of Lading (eBL) envelope transfers.

## Overview

This project implements both sender and receiver platforms for the PINT API, demonstrating:
- eBL envelope transfer workflow
- JWS digital signatures 
- SHA-256 checksum validation
- Additional document transfers
- Transfer chain tracking

```
pint-demo/
├── app/
│   ├── cmd/
│   │   ├── pint-receiver/    # Receiver platform HTTP server
│   │   └── pint-sender/      # Sender platform CLI
│   ├── internal/
│   │   ├── cli/              # Sender CLI commands
│   │   ├── crypto/           # Cryptographic operations
│   │   ├── config/           
│   │   ├── logger/           
│   │   ├── server/           # HTTP server
│   │   └── database/         # SQLC generated code
│   ├── sql/
│   │   ├── schema/           # Database migrations
│   │   └── queries/          # SQL queries
│   ├── go.mod
│   └── sqlc.yaml
├── docker-compose.yml
├── Makefile
```

## Getting Started

### Prerequisites

- Docker 

### Quick Start

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
