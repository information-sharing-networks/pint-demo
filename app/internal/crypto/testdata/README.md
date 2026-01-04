# Test Data for Crypto Package

The `certs/` directory contains test certificates and keys for use in testing the crypto package.
Certificates expire in 2036 (except the expired certificate)

## Regenerating Certificates

If you need to regenerate the test certificates:

```bash
cd app/internal/crypto/testdata/scripts
./generate-test-certs.sh -d ../certs
```

**Note:** The "expired" certificate will be generated to expire in 1 day, so you will need to wait for a day before using it in tests.

The certs created are:

### Self-Signed Certificate
- **Files:** `self-signed-server.crt`, `self-signed-server.key`
- CN=self-signed.example.com

### Valid Certificate Chain
- **Root CA:** `root-ca.crt`, `root-ca.key`
  - CN=Test Root CA
- **Intermediate CA:** `intermediate-ca.crt`, `intermediate-ca.key`
  - CN=Test Intermediate CA
- **Leaf Certificate:** `valid-server.crt`, `valid-server.key`
  - CN=valid.example.com
- **Full Chain:** `valid-fullchain.crt` 

### Expired Certificate Chain
- **Root CA:** `root-ca.crt`, `root-ca.key`
  - CN=Test Root CA
- **Intermediate CA:** `intermediate-ca.crt`, `intermediate-ca.key`
  - CN=Test Intermediate CA
- **Leaf Certificate:** `expired-server.crt`, `expired-server.key`
  - CN=expired.example.com
- **Full Chain:** `expired-fullchain.crt` 

### Invalid Certificate Chain  (leaf signed by untrusted CA not in chain)
- **Untrusted CA:** `untrusted-ca.crt`, `untrusted-ca.key`
  - CN=Untrusted Test CA
- **Leaf Certificate:** `invalid-chain-server.crt`, `invalid-chain-server.key`
  - CN=invalid-chain.example.com
 - **Full Chain:** `invalid-chain-fullchain.crt`
