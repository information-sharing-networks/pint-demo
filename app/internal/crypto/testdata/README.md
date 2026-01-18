# Test Data for Crypto Package

## Platform Registry

The `platform-registry.csv` file contains a test registry of platforms for use in testing the crypto package.
The file is based on the DCSA registry file found at https://github.com/dcsaorg/DCSA-OpenAPI/raw/master/reference-data/eblsolutionproviders-v3.0.0.csv

 The JSON is based on the DCSA openapi v3.0.2 sample data, and the computed fields (JWS and checksums) were calculated indepenently of the pint-demo code so they can be used in testing.

## Transport Documents
the `transport-documents` directory contains sample JSON that would be used in an issuance request. 

## PINT Transfers
the `pint-transfers` directory contains json that would be used in a PINT transfer.  The json is based on the DCSA openapi v3.0.0 PINT sample data.

see below for details of the keys used in signing the sample data content

## Test Certificates and Keys

The `certs/` and `keys/` directories contain test certificates and key pairs for use in testing the crypto package. 

The valid transport docs and PINT transfers were signed with the `../keys/ed25519-eblplatform.example.com.private.jwk` and `../keys/ed25519-carrier.example.com.private.jwk` keys. 

The fullchain certs (`../certs/ed25519-eblplatform.example.com-fullchain.crt` and `../certs/ed25519-carrier.example.com-fullchain.crt`) are included in the JWS headers.

the leaf certificates were created with Subject.Organization fields to simulate EV/OV certificates.  The Root and Intermediate CAs are self-signed.

There are sample expired and invalid certificates for testing.

**Certificates expire in 10 years** (except the expired cert which expires 1 day after generation)

- **All leaf certificates** have matching JWK and PEM key pairs (same cryptographic key in different formats)

**Note** If you regenerate the keys and/or certificates, you will need to regenerate the signatures in the sample data (see below)

### Regenerating Test Keys and Certificates

The `scripts/` directory contains scripts to generate the test certificates and keys.  You should not need to run these scripts unless you need to regenerate the test keys and certificates.


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


