
![ci](https://github.com/information-sharing-networks/pint-demo/actions/workflows/ci.yml/badge.svg)


# PINT Demo

[Quick Start](#quick-start) |
[Concepts](#concepts) |
[Project Layout](#project-layout) |
[Key Generation](#generating-key-pairs) |
[Client](#client) |
[Server](#server)


A demonstration implementation of the DCSA PINT (Platform Interoperability) API v3.0.0 for electronic Bill of Lading (eBL) envelope transfers.

# Getting Started

### Prerequisites

To run the app you need to install:
- [Docker Desktop](https://docs.docker.com/get-docker)

... and if you plan to make changes to the code (or want to run the go tests):
- [Go 1.25.4 or above](https://go.dev/doc/install)

### Quick Start

#### 1. create a .env file in the root of the project:
```bash
# Path to CSV file containing the registry of all approved eBL PINT participants
REGISTRY_PATH="internal/crypto/testdata/platform-registry/eblsolutionproviders.csv"

# Path to private key JWK file used for signing PINT messages
SIGNING_KEY_PATH="internal/crypto/testdata/keys/ed25519-eblplatform.example.com.private.jwk"

# Directory containing manually configured public keys from other PINT participants in JWK format
# The keymanager will load any public key in the directory that has a matching kid in the registry
# (other keys will be ignored).
# Supported file extensions: .jwk, .jwks, .jwks.json
# The keymanager expects one key per file.
MANUAL_KEYS_DIR="internal/crypto/testdata/keys"

# DCSA Code of the platform this instance represents (from the registry)
PLATFORM_CODE="EBL1"

# Path to X.509 certificate(s) in PEM format (optional)
# When set, certificate(s) are included in the JWS x5c header for non-repudiation purposes
# Can be a single leaf certificate or a full chain (leaf + intermediates)
# The leaf certificate's public key must match the private key at SIGNING_KEY_PATH
X5C_CERT_PATH="internal/crypto/testdata/certs/ed25519-eblplatform.example.com-fullchain.crt"

# Path to custom root CA certificate(s) in PEM format (optional)
# Use this when certificates are issued by a private PKI
# Leave unset to validate against system root CAs
# Note: if specifying a custom root, all participants in the PINT network must share the same root CA
# x5c headers from other participants will be validated against this root CA
X5C_CUSTOM_ROOTS_PATH="internal/crypto/testdata/certs/root-ca.crt"

# Database connection string (docker db container for dev)
DATABASE_URL="postgres://pint-dev:@db:5432/pint_demo?sslmode=disable"
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
   - Start the app container (pint-server service) on http://localhost:8080
  

you can override default configs by setting environment variables when you start the server, e.g.

```bash
SKIP_JWK_CACHE=true make docker-up    # Set true to disable JWK caching
PORT=8081 make docker-up              # server port (default is 8080)
LOG_LEVEL=info make docker-up         # debug, info, warn, error (default is debug)
MIN_TRUST_LEVEL=2  make docker-up     # 1=EV/OV, 2=DV, 3=NoX5C (defaults to the 1)
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

to reset the database and restart the containers:
```bash
make docker-reset
```

## Concepts

### Key distribution
This app implements a hybrid approach to key distribution:
- **Dynamic JWK endpoints**: Automatically fetches and caches public keys from configured JWKS endpoints. The list of endpoints is retrieved from the DCSA registry.
- **Manual keys**: Supports manually configured keys for testing or private networks where keys are exchanged out of band.

Keys are looked up by the KID retrieved from JWS headers. The KID is derived from the public key thumbprint (the first 8 bytes of the SHA-256 hash in hex format).

### Platform registry
This implementation relies on a platform registry that contains the list of all approved eBL PINT participants (carriers, banks and ebl platforms). 

The registry is used for two purposes:
- **Authorization**: The registry is the single source of truth for which platforms are allowed to participate in the PINT network. This is used to prevent platforms from joining the network without first signing up to the DCSA agreement.
- **Security**: the registry contains the JWKS endpoint (if applicable) for each platform and - where no JWKS endpoint is specified - the KID of the manually configured key for the platform. This information is used to ensure that the public keys needed to verify JWS signatures are only retrieved from trusted locations.

This list is configured via the `DCSA_REGISTRY_PATH` environment variable.

For the purpose of this demo the registry is based on a local file (`app/internal/crypto/testdata/platform-registry/eblsolutionproviders.csv`),
 but in a real deployment the registry would be served from a secure endpoint and cover all participants in the PINT network.

### Trust model and non-repudiation
This app implements an experimental approach to verifying the legal entities operating platforms in PINT exchanges. While DCSA does not mandate a specific verification method, this implementation extends their signature approach by enabling platforms to include x5c headers in the JWS.

The x5c header contains a certificate chain that cryptographically binds the public key to a verified legal entity. The app validates this chain against trusted root certificates, which can be either system-provided roots or custom roots configured for the deployment.

The x5c is optional - there are three tiers of trust supported:
1. **TrustLevelEVOV**: x5c with EV/OV certificates (organisation verified by CA) - recommended for production
2. **TrustLevelDV**: x5c with DV certificates (domain ownership verified by CA)
3. **TrustLevelNoX5C**: no x5c (no verification of legal entity) - testing only

The platform can enforce a minimum trust level policy via the `MIN_TRUST_LEVEL` environment variable (1=EV/OV, 2=DV, 3=NoX5C). Signatures below the minimum trust level are rejected.

Per DCSA, it is not clear how PINT networks operating at the 2nd and 3rd trust levels could support non-repudiation, but they are supported in case they are needed.

Note: the public key in the x5c certificate must match the key pair used by platform to sign the JWS - see the *Generating Key Pairs* section below for more information.

### Signatures
DCSA do not specify which algorithms should be used for signing. This implementation supports both Ed25519 and RSA (Ed25519 is recommended for new implementations).

### Validation
This app implements all the cryptographic validation steps recommended in the DCSA *Digital Signatures Implementation Guide*. It only does basic validation of the transport document JSON - schema validation is not implemented.

### Signing keys
DCSA does not specify which algorithms should be used for signing. This implementation supports both Ed25519 and RSA (Ed25519 is recommended for new implementations).

## Project Layout
```
pint-demo/
   ├── app/
   │   ├── cmd/
   │   │   ├── keygen/                        # Key generation CLI
   │   │   ├── pint-server/                 # Receiver platform HTTP server
   │   │   └── pint-client/                   # Sender platform CLI
   │   ├── internal/
   │   │   ├── client/                        # PINT API client 
   │   │   ├── cli/                           # CLI commands
   │   │   ├── config/                        # server configuration
   │   │   ├── crypto/                        # JWS signing/verification, key management
   │   │   │── database/                      # SQLC generated code
   │   │   │── ebl/                           # eBL creation/verification
   │   │   │── issuance/                      # Issuance API handlers
   │   │   ├── logger/                        # logging
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
## Generating key pairs

The `keygen` command is part of the app and can be used to create a new key pair for a PINT platform:

```bash
go run cmd/keygen/main.go --type ed25519 --hostname eblplatform.example.com --outputdir ./keys
 ```

the output files are:

- `eblplatform.example.com.private.jwk`  (for signing PINT messages)
- `eblplatform.example.com.public.jwk`   (publish at https://eblplatform.example.com/.well-known/jwks.json)
- `eblplatform.example.com.private.pem`  (for creating Certificate Signing Request to send to your Certificate Authority)
- `eblplatform.example.com.public.pem`   (included for completeness and used in testing)

Note the pub key files are provided for convenience - when starting the server, you just need to specify the private key used for signatures and the server will make the correspoding public key available via the JWKS endpoint.

## x5c certificates
As explained in the *Concepts* section above, including an x5c certificate chain in the eBL JWS signatures is optional, but recommended for non-repudiation purposes (EV or OV certs are recommended for production).


If you want to include x5c, you will need to create a certificate for the PINT platform and have it signed by a Certificate Authority (CA).


By default the platform uses the system's default root CAs for x5c verification. You can also configure custom root CAs (see the *Environment Variables* section below). Custom roots are used in testing and can also be used in private networks or where you want to use a selected subset of the default root CAs.

You must use your eBL platform signing private key to sign the certificate request, since the public key in the certificate must match the key pair used by platform to sign the JWS.

this app does not support cert generation, but some certs are provided in `app/internal/crypto/testdata/certs` for testing purposes.

all certs are expected to be X.509 in PEM format.

## Client
the `ebl` package provides high-level functions that can be use to create *PINT Transfers* (EBL_PINT_v3.0.0). 

There is also a basic implemenation of DCSA *eBL Issuance Requests*  (EBL_ISS_v3.0.2) to help create end-2-end demos.

These functions take care of all the required cryptographic steps needed to create and validate PINT and issuance requests. They hide the details of the cryptographic operations and focus on the business logic of the PINT and issuance workflows.  See the crypto package for the low level function that they use.

a demo CLI client is provided in `app/cmd/pint-client/main.go` - this is work-in-progress

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

### Testing
In addition to the unit tests, there is a set of reference data in `app/internal/crypto/testdata/` that is used in the automated tests. This includes:
- Test certificates and keys (Ed25519 and RSA)
- Test transport documents
- Test PINT transfer data

The signatures in the test data were computed out of band using the test keys.

See `app/internal/crypto/testdata/README.md` for details on how to regenerate the test keys and certificates if needed.

## Server
There is a single server implementation in `app/cmd/pint-server/main.go` - this is work-in-progress

see the http://localhost:8080/docs for the API docs

The pint-server service exposes:
- `GET /health` - Health check endpoint
- `GET /.well-known/jwks.json` - JWK set endpoint (public key for this instance of the server)
- `GET /docs` - API documentation (ReDoc)
- `GET /swagger.json` - OpenAPI specification
- `POST /v3/envelopes` - Receive PINT transfer envelopes 

Support for the following endpoints is planned but not yet implemented:
- `PUT /v3/ebl-issuance-requests` - Receive eBL issuance request
- `PUT /v3/envelopes/{envelopeReference}/additional-documents/{documentChecksum}` - Add additional documents to a PINT transfer envelope 
- `PUT /v3/envelopes/{envelopeReference}/finish-transfer` - Finish a PINT transfer envelope

## Testing
end-2-end testing for the http server is planned but not yet implemented.
