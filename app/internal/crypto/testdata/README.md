# Test Data for Crypto Package

## Platform Registry

The `platform-registry.csv` file contains a test registry of platforms for use in testing the crypto package.
The file is based on the DCSA registry file found at https://github.com/dcsaorg/DCSA-OpenAPI/raw/master/reference-data/eblsolutionproviders-v3.0.0.csv


## Transport Documents
the `transport-documents` directory contains sample JSON that would be used in an issuance request.  The JSON is based on the DCSA openapi v3.0.2 sample data, but with manually computed fields for testing.  The manually computed fields are:

- `eBLVisualisationByCarrier` - an optional field in the DCSA Issuance Request that allows the carrier to provide a human-readable visualization of the eBl.  The `content` field is base64 encoded string of the binary content of the associated visualisation file `HHL71800000.pdf`.    
- `issuanceManifestSignedContent` - this field is used by receiving parties to verify the 3 parts of the transport docuement (document details, issueTo, and eBLVisualisationByCarrier) have not been tampered with since issuance.  This field is created in two steps - firstly create the intermediary `IssuanceManifest.json` file, and then sign that file with the private key of the carrier (`ed25519-carrier.example.com.private.jwk` or `rsa-carrier.example.com.private.jwk` in this case)  


## PINT Transfers
the `pint-transfers` directory contains json that would be used in a PINT transfer.  The json is based on the DCSA openapi v3.0.0 PINT sample data, but with manually computed fields for testing.  The manually computed fields are:

- `envelopeManifestSignedContent` - this field is used by receiving parties to verify the 3 parts of the transport docuement (document details, issueTo, and eBLVisualisationByCarrier) have not been tampered with since issuance.  This field is created by creating the intermediary `EnvelopeManifest.json` file, and then signing that file with the private key of the sending platform (`ed25519-eblplatform.example.com.private.jwk` or `rsa-eblplatform.example.com.private.jwt` in this case)

see below for details of the keys used in signing the sample data content

## Test Certificates and Keys

The `certs/` and `keys/` directories contain test certificates and key pairs for use in testing the crypto package.

### Regenerating Test Keys and Certificates

** Note ** the sample data in `transport-documents/` and `pint-transfers/` depends on the keys and certificates in this directory.  If you regenerate the keys and certificates, you will need to regenerate the signatures in the sample data.

To regenerate all test keys and certificates:

```bash
cd /path/to/pint-demo
./app/internal/crypto/testdata/scripts/generate-test-keys-and-certs.sh -d project_root_dir
```

This script:
1. Generates key pairs using `keygen` (outputs JWK and PEM formats)
2. Outputs test certificates for testing

to regenerate the signatures in the sample data, use the `recompute-signatures.sh` script:

```bash
cd /path/to/pint-demo
./app/internal/crypto/testdata/scripts/recompute-signatures.sh -d project_root_dir
```
... you will need to manually add the signatures to the sample data.

if you alter any of the json content in the sample data, you will need to regenerate the signatures and checksums.

### Generated Files

all certs and keys are ed2519 unless otherwise noted

#### 1. Valid Certificate Chain
- **Purpose:** Test valid certificate chain validation
- **Root CA:** `certs/root-ca.crt`, `certs/root-ca.pem`
  - CN=Test Root CA
- **Intermediate CA:** `certs/intermediate-ca.crt`, `certs/intermediate-ca.pem`
  - CN=Test Intermediate CA
- **Leaf Certificate:** `certs/eblplatform.example.com.crt`
  - CN=eblplatform.example.com
- **Full Chain:** `certs/eblplatform.example.com-fullchain.crt`
- **Key Pair (JWK + PEM):**
  - `keys/eblplatform.example.com.private.jwk` (for signing PINT messages)
  - `keys/eblplatform.example.com.public.jwk` (for publishing to JWKS endpoint)
  - `keys/eblplatform.example.com.private.pem` (used to create the certificate)

  rsa-eblplatform.example.com (RSA key) and carrier.example.com are also generated and are valid.

#### 2. Expired Certificate Chain
- **Purpose:** Test expired certificate rejection
- **Leaf Certificate:** `certs/eblplatform-expired.example.com.crt`
  - CN=eblplatform-expired.example.com
  - **Expires in 1 day from generation**
- **Full Chain:** `certs/eblplatform-expired.example.com-fullchain.crt`
- **Key Pair (JWK + PEM):**
  - `keys/eblplatform-expired.example.com.private.jwk`
  - `keys/eblplatform-expired.example.com.public.jwk`
  - `keys/eblplatform-expired.example.com.private.pem`


**Note:** The "expired" certificate will be generated to expire in 1 day, so you will need to wait for a day before using it in tests.

#### 3. Invalid Certificate Chain
- **Purpose:** Test certificate chain validation failure (leaf signed by untrusted CA)
- **Untrusted CA:** `certs/untrusted-ca.crt`, `certs/untrusted-ca.pem`
  - CN=Untrusted Test CA
- **Leaf Certificate:** `certs/eblplatform-invalid.example.com.crt`
  - CN=eblplatform-invalid.example.com
- **Full Chain:** `certs/eblplatform-invalid.example.com-fullchain.crt` (contains wrong CA chain)
- **Key Pair (JWK + PEM):**
  - `keys/eblplatform-invalid.example.com.private.jwk`
  - `keys/eblplatform-invalid.example.com.public.jwk`
  - `keys/eblplatform-invalid.example.com.private.pem`

##

- **All leaf certificates** have matching JWK and PEM key pairs (same cryptographic key in different formats)
- **Certificates expire in 10 years** (except the expired cert which expires in 1 day)
