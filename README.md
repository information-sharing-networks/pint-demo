
![ci](https://github.com/information-sharing-networks/pint-demo/actions/workflows/ci.yml/badge.svg)

# PINT Demo

A demonstration implementation of the DCSA PINT (Platform Interoperability) API v3.0.0 for electronic Bill of Lading (eBL) envelope transfers.

## Getting Started

### Prerequisites

To run the app you need to install:
- [Docker Desktop](https://docs.docker.com/get-docker)

... and if you plan to make changes to the code:
- [Go 1.25.4 or above](https://go.dev/doc/install)

### Quick Start

#### 1. create a .env file in the root of the project:
```bash
SIGNING_KEY_PATH="internal/crypto/testdata/keys/ed25519-eblplatform.example.com.private.jwk"
MANUAL_KEYS_DIR="internal/crypto/testdata/keys"
REGISTRY_PATH="internal/crypto/testdata/platform-registry/eblsolutionproviders.csv"
PLATFORM_CODE="EBL1"
```

#### 2. Start the development environment:
   ```bash
   cd pint-demo
   . .env
   make docker-up
   ```

   This will:
   - Start the db contaienr (PostgreSQL 17)
   - Generate SQLC code and API docs
   - Run database migrations
   - Start the app container (pint-receiver service) on http://localhost:8080
  

you can override defaults configs by setting environment variables when you start the server, e.g.

```bash
SKIP_JWK_CACHE=false make docker-up                 # Set true to disable JWK caching
PORT=8081 make docker-up                            # server port (default is 8080)
LOG_LEVEL=info make docker-up                       # debug, info, warn, error (default is debug)
MIN_TRUST_LEVEL=2                                   # 1=EV/OV, 2=DV, 3=NoX5C (defaults to the 1, the highest trust level)
```
Other configs have sensible defaults (see `app/internal/server/config/config.go` for the full list).

## Development Tools

All development tools are available via Docker (no local installation needed):

```bash
make sqlc      # Generate SQLC code
make migrate   # Run database migrations
make docs      # generate swagger (openAPI) docs
make swag-fmt  # format swag comments
make test      # Run tests
make check     # Run all checks (fmt, vet, test, lint, security)
make psql      # run psql against the dev database
```

if there are updates to the go dependencies (go.mod), you will need to rebuild the app container:

```bash
docker compose up build app
```


# Concepts

## Key distribution
This app implements a hybrid approach to key distribution:
- **Dynamic JWK endpoints**: Automatically fetches and caches public keys from configured JWKS endpoints. The list of endpoints is retrieved from the DCSA registry.
- **Manual keys**: Supports manually configured keys for testing or private networks where keys are exchanged out of band.

Keys are looked up by the KID retrieved from JWS headers. Per the DCSA recommendation, the KID is the thumbprint of the public key.

## Platform registry
This implementation relies on a platform registry that contains the list of all approved eBL PINT participants (carriers, banks and ebl platforms). 

The registry is used for two purposes:
- **Authorization**: The registry is the single source of truth for which platforms are allowed to participate in the PINT network. This is used to prevent platforms from joining the network without first signing up to the DCSA agreement.
- **Security**: the registry contains the JWKS endpoint (if applicable) for each platform and - where no JWKS endpoint is specified - the KID of the manually configured key for the platform. This information is used to ensure that the public keys needed to verify JWS signatures are only retrieved from trusted locations.

This list is configured via the `DCSA_REGISTRY_PATH` environment variable.

For the purpose of this demo the registry is based on a local file (`app/internal/crypto/testdata/platform-registry/eblsolutionproviders.csv`),
 but in a real deployment the registry would be served from a secure endpoint and cover all participants in the PINT network.

## Trust model and non-repudiation
This app implements an experimental approach to verifying the legal entities operating platforms in PINT exchanges. While DCSA does not mandate a specific verification method, this implementation extends their signature approach by enabling platforms to include x5c headers in the JWS.

The x5c header contains a certificate chain that cryptographically binds the public key to a verified legal entity. The app validates this chain against trusted root certificates, which can be either system-provided roots or custom roots configured for the deployment.

The x5c is optional - there are three tiers of trust supported:
1. **TrustLevelEVOV**: x5c with EV/OV certificates (organisation verified by CA) - recommended for production
2. **TrustLevelDV**: x5c with DV certificates (domain ownership verified by CA)
3. **TrustLevelNoX5C**: no x5c (no verification of legal entity) - testing only

The platform can enforce a minimum trust level policy via the `MIN_TRUST_LEVEL` environment variable (1=EV/OV, 2=DV, 3=NoX5C). Signatures below the minimum trust level are rejected.

Per DCSA, it is not clear how PINT networks operating at the 2nd and 3rd trust levels could support non-repudiation, but they are supported in case they are needed.

Note: the public key in the x5c certificate must match the key pair used by platform to sign the JWS - see the *Generating Key Pairs* section below for more information.

## Signatures
DCSA do not specify which algorithms should be used for signing. This implementation supports both Ed25519 and RSA (Ed25519 is recommended for new implementations).

## Validation
This app implements all the cryptographic validation steps recommended in the DCSA *Digital Signatures Implementation Guide*. It only does basic validation of the transport document JSON - schema validation is not implemented.

## Project Layout
```
pint-demo/
   ├── app/
   │   ├── cmd/
   │   │   ├── keygen/                        # Key generation CLI
   │   │   ├── pint-receiver/                 # Receiver platform HTTP server
   │   │   └── pint-sender/                   # Sender platform CLI
   │   ├── internal/
   │   │   ├── client/                        # PINT API client 
   │   │   ├── cli/                           # CLI commands
   │   │   ├── config/                        # server configuration
   │   │   ├── crypto/                        # JWS signing/verification, key management
   │   │   │── database/                      # SQLC generated code
   │   │   │── ebl/                           # eBL creation/verification
   │       ├── logger/                        # logging
   │   │   │── pint/                          # PINT API handlers
   │   │   └── server/                        # HTTP server
   │   ├── sql/
   │   │   └── schema/                        # Database migrations
   │   │   └── queries/                       # SQL queries
   │   ├── go.mod
   │   └── sqlc.yaml
   ├── docker-compose.yml
   └── Makefile
```
## Creating key pairs for PINT platforms

The `keygen` command is part of the app and can be used to create a new key pair for a PINT platform:

```bash
go run cmd/keygen/main.go --type ed25519 --hostname eblplatform.example.com --outputdir ./keys
 ```

the output files are:

- `eblplatform.example.com.private.jwk`  (for signing PINT messages)
- `eblplatform.example.com.public.jwk`   (publish at https://eblplatform.example.com/.well-known/jwks.json)
- `eblplatform.example.com.private.pem`  (for creating Certificate Signing Request to send to your Certificate Authority)
- `eblplatform.example.com.public.pem`   (included for completeness and used in testing)

# Usage
the `ebl` package provides high-level functions that can be use to create *PINT Transfers* (EBL_PINT_v3.0.0). There is also a basic implemenation of DCSA *eBL Issuance Requests*  (EBL_ISS_v3.0.2) to help create end-2-end demos.

These functions show the overall logic of creating and validating requsests. The low level functions used to do the actual cryptographic operations are in  `crypto`  (see below).

### Creating an Issuance Request 
To create an initial issuance request that is sent from the carrier to the ebl platform (`PUT /v3/ebl-issuance-requests`), use the `CreateIssuanceRequest` function.

See `app/internal/ebl/issuance_request_test.go` for example usage.

### Creating a PINT Transfer
To create a PINT transfer envelope that is sent from one ebl platform to another (`POST /v3/envelopes`), use the high-level `CreateEnvelopeTransfer` function.

See `app/internal/ebl/envelope_transfer_test.go` for example usage. 

### Verifying a PINT Transfer
To verify a PINT transfer envelope that is received by an ebl platform (`POST /v3/envelopes`), use the `VerifyEnvelopeTransfer` function.

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
In addition to the unit tests, there is a set of reference data in `app/internal/crypto/testdata/` that is used in the automated tests. This includes:
- Test certificates and keys (Ed25519 and RSA)
- Test transport documents
- Test PINT transfer data

The signatures in the test data were computed out of band using the test keys.

See `app/internal/crypto/testdata/README.md` for details on how to regenerate the test keys and certificates if needed.

## API Endpoints

The pint-receiver service exposes:
- `GET /health` - Health check endpoint

Support for the following endpoints is planned but not yet implemented:
- `PUT /v3/ebl-issuance-requests` - Receive eBL issuance request
- `POST /v3/envelopes` - Receive PINT transfer envelopes 
- `PUT /v3/envelopes/{envelopeReference}/additional-documents/{documentChecksum}` - Add additional documents to a PINT transfer envelope 
- `PUT /v3/envelopes/{envelopeReference}/finish-transfer` - Finish a PINT transfer envelope
