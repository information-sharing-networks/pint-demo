# PINT Demo

A demonstration implementation of the DCSA PINT (Platform Interoperability) API v3.0.0 for electronic Bill of Lading (eBL) envelope transfers.


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

## Configuration

Key environment variables (all have sensible defaults):

```bash
# Required for production
DATABASE_URL=postgres://user:pass@host:5432/dbname?sslmode=disable
SECRET_KEY=your-secret-key-here

# Platform identity
PLATFORM_ID=platform-a.example.com
PLATFORM_NAME="Platform A"

# Trust and security
KEY_MANAGER_MIN_TRUST_LEVEL=1          # 1=EV/OV, 2=DV, 3=NoX5C
DCSA_REGISTRY_URL=https://registry.dcsa.org/ebl-solution-providers.json
SKIP_JWK_CACHE=false                   # Set true to disable JWK caching

# Server settings
PORT=8080
ENVIRONMENT=development                # development, staging, production
LOG_LEVEL=info                         # debug, info, warn, error
```

See `.env.example` for a complete list of configuration options.

# Concepts

## Key distribution
This app implements a hybrid approach to key distribution:
- **Dynamic JWK endpoints**: Automatically fetches and caches public keys from `https://<domain>/.well-known/jwks.json` with auto-refresh (15min-24hr intervals)
- **Manual keys**: Supports manually configured keys stored in the database for testing or private networks

Keys are looked up by the KID in the JWS header. Per the DCSA recommendation, the KID is the thumbprint of the public key.

As an additional precaution the app will also check the platform hostname is in an approved list of participating platforms. This list is configured via the `DCSA_REGISTRY_URL` environment variable. This is done to prevent platforms from joining the network without first singing up to the DCSA agreement.

## Trust model and non-repudiation
This app implements an experimental approach to verifying the legal entities operating platforms in PINT exchanges. While DCSA does not mandate a specific verification method, this implementation extends their signature approach by enabling platforms to include x5c headers in the JWS.

The x5c header contains a certificate chain that cryptographically binds the public key to a verified legal entity. The app validates this chain against trusted root certificates, which can be either system-provided roots or custom roots configured for the deployment.

The x5c is optional - there are three tiers of trust supported:
1. **TrustLevelEVOV**: x5c with EV/OV certificates (organisation verified by CA) - recommended for production
2. **TrustLevelDV**: x5c with DV certificates (domain ownership verified by CA)
3. **TrustLevelNoX5C**: no x5c (no verification of legal entity) - testing only

The platform can enforce a minimum trust level policy via the `KEY_MANAGER_MIN_TRUST_LEVEL` environment variable (1=EV/OV, 2=DV, 3=NoX5C). Signatures below the minimum trust level are rejected.

Per DCSA, it is not clear how PINT networks operating at the 2nd and 3rd trust levels could support non-repudiation, but they are supported in case they are needed.

## Signatures
DCSA do not specify which algorithms should be used for signing. This implementation supports both Ed25519 and RSA (Ed25519 is recommended for new implementations).

## Validation
This app implements all the cryptographic validation steps recommended in the DCSA *Digital Signatures Implementation Guide*. It only does basic validation of the transport document JSON - schema validation is not implemented.

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

# Usage
the `ebl` package provides high-level functions that can be use to create *PINT Transfers* (EBL_PINT_v3.0.0). There is also a minimal implemenation of DCSA *eBL Issuance Requests*  (EBL_ISS_v3.0.2) to help create end-2-end demos

These functions show the overall logic of creating and validating requsests. These functions use the low level functions in `crypto` to do the actual cryptographic operations (see below).

### Creating an Issuance Request 
To create an initial issuance request that is sent from the carrier to the ebl platform (`PUT /v3/ebl-issuance-requests`), use the high-level `CreateIssuanceRequest` function.

See `app/internal/ebl/issuance_request_test.go` for example usage.

### Creating a PINT Transfer
To create a PINT transfer envelope that is sent from one ebl platform to another (`POST /v3/envelopes`), use the high-level `CreateEnvelopeTransfer` function.

See `app/internal/ebl/envelope_transfer_test.go` for example usage. 

### Verifying a PINT Transfer
To verify a PINT transfer envelope that is received by an ebl platform (`POST /v3/envelopes`), use the high-level `VerifyEnvelopeTransfer` function.

See `app/internal/ebl/envelope_verification_test.go` for example usage. 

the verification process follows the recommendations in the DCSA *Digital Signatures Implementation Guide*.

## the crypto package
The crypto package supports:
- Signature creation and verification
- Option to use Ed25519 or RSA algorithms
- Option to include x5c certificate chain in JWS for non-repudiation
- Trust levels - EV/OV, DV, NoX5C
- Manual and dynamic (JWK endpoint) key distribution

## Testing
There is a set of reference data in `app/internal/crypto/testdata/` that is used in the tests. This includes:
- Test certificates and keys (Ed25519 and RSA)
- Test transport documents
- Test PINT transfer data

The signatures in the test data were computed out of band using the test keys and are used as part of the automated tests.

See `app/internal/crypto/testdata/README.md` for details on how to regenerate the test keys and certificates if needed.

## API Endpoints

The pint-receiver service exposes:
- `GET /health` - Health check endpoint
- `GET /.well-known/jwks.json` - Public JWK set for signature verification


Support for the following endpoints is planned but not yet implemented:
- `PUT /v3/ebl-issuance-requests` - Receive eBL issuance requests (DCSA EBL_ISS v3.0.2)
- `POST /v3/envelopes` - Receive PINT transfer envelopes (DCSA PINT v3.0.0)
- `PUT /v3/envelopes/{envelopeReference}/additional-documents/{documentChecksum}` - Add additional documents to a PINT transfer envelope (DCSA PINT v3.0.0)
- `PUT /v3/envelopes/{envelopeReference}/finish-transfer` - Finish a PINT transfer envelope (DCSA PINT v3.0.0)
