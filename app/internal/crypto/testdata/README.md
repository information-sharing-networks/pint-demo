# Test Data for Crypto Package

## Platform Registry

The `platform-registry.csv` file contains a test registry of platforms for use in testing the crypto package.
The file is based on the DCSA registry file found at https://github.com/dcsaorg/DCSA-OpenAPI/raw/master/reference-data/eblsolutionproviders-v3.0.0.csv

## Test Certificates and Keys

The `certs/` and `keys/` directories contain test certificates and key pairs for use in testing the crypto package.

### Regenerating Test Keys and Certificates

To regenerate all test keys and certificates:

```bash
cd /path/to/pint-demo
./app/internal/crypto/testdata/scripts/generate-test-keys-and-certs.sh -d .
```

This script:
1. Generates key pairs using `keygen` (outputs JWK and PEM formats)
2. Creates certificate chains using the generated keys
3. Outputs test certificates for various scenarios

**Note:** The "expired" certificate will be generated to expire in 1 day, so you will need to wait for a day before using it in tests.

### Generated Files

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
