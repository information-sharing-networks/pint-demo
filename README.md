# PINT Demo

A demonstration implementation of the DCSA PINT (Platform Interoperability) API v3.0.0 for electronic Bill of Lading (eBL) envelope transfers.

## Project Layout

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
│   │   └── ebl/              # eBL API functions
│   ├── sql/
│   │   ├── schema/           # Database migrations
│   │   └── queries/          # SQL queries
│   ├── go.mod
│   └── sqlc.yaml
├── docker-compose.yml
├── Makefile
```

# the crypto package supports:
- Signature creation and verification per DCSA *Digital Signatures Implementation Guide*
- Option to use Ed25519 or RSA algorithms
- Option to include x5c certificate chain in JWS for non-repudiation 
- Trust levels - EV/OV, DV, NoX5C
- Manual and dymanic (JWK endpoint) key distribution 

there is a full set of test data in `app/internal/crypto/testdata/`. This includes:
- test certificates and keys
- test transport documents
- test pint transfer data  

signatures in the test document were computed out of band using the test keys and are used as part of the automated tests.

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
make test      # Run tests
make check     # Run all checks (fmt, vet, test, lint, security)
```


if there are updates to the go dependencies (go.mod), you will need to rebuild the app container:

```bash
docker compose up --build app
```

# Usage

## Creating key pairs for PINT platforms

To create a new key pair for a PINT platform, use the `keygen` command:

```bash
go run cmd/keygen/main.go --type ed25519 --hostname eblplatform.example.com --outputdir ./keys
 ```

the output files are:

- `eblplatform.example.com.private.jwk`  (for signing PINT messages)
- `eblplatform.example.com.public.jwk`   (publish at https://eblplatform.example.com/.well-known/jwks.json)
- `eblplatform.example.com.private.pem`  (for creating CSR to send to CA)
- `eblplatform.example.com.public.pem`   (included for completeness and used in testing)

## Using the included packages to create DSCA API messages

you can use the pint-demo packages to create DCSA *eBL Issuance Requests*  (EBL_ISS_v3.0.2) and *PINT Transfers* (EBL_PINT_v3.0.0).  These are for demonstration purposes and show how to use the crypto package to create valid PINT and issuance requests.

### Creating an Issuance Request 
To create an initial issuance request that is sent from the carrier to the ebl platform (`PUT /v3/ebl-issuance-requests`), use the high-level `CreateIssuanceRequest` function.

See `app/internal/ebl/issuance_request_test.go` for example usage.

### Creating a PINT Transfer
To create a PINT transfer envelope that is sent from one ebl platform to another (`POST /v3/envelopes`), use the high-level `CreateEnvelopeTransfer` function.

See `app/internal/ebl/envelope_transfer_test.go` for example usage. 

## TODO 
**support for remaining PINT API endpoints**
- /v3/receiver-validation 
- /v3/envelopes/{id}/finish-transfer 

**demo PINT service and clients**

the demo service and clients are not yet fully implemented, but will simulate a simple PINT API workflow:
carrier > platform 1 > platform 2 > carrier