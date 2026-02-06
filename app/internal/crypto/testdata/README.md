# Test Data for Crypto Package

## Platform Registry

The `platform-registry.csv` file contains a test registry of platforms for use in testing the crypto package.
The file is based on the DCSA registry file found at https://github.com/dcsaorg/DCSA-OpenAPI/raw/master/reference-data/eblsolutionproviders-v3.0.0.csv

 The JSON is based on the DCSA openapi v3.0.2 sample data, and the computed fields (JWS and checksums) were calculated indepenently of the pint-demo code so they can be used in testing.

## Transport Documents
the `transport-documents` directory contains sample JSON that would be used in an issuance request. 

## PINT Transfers
the `pint-transfers` directory contains json that would be used in a PINT transfer.  The json is based on the DCSA openapi v3.0.0 PINT sample data.

use HHL71800000-ebl-envelope-ed25519.json for testing transfers:
the sample ebl transfer request `HHL71800000-ebl-envelope-ed25519.json` includes 2 additional docs + an ebl visualization.  The response should indicate that 3 additional documents are required. See enelope-manifest.json for the expected checksums and metadata.

This envelope was signed by ebl1 and the receiving platform is EBL2 (rsa-eblplatform.example.com). The test server should be started as EBL2 as per the config in  `app/test/integration/env_setup.go`.

the `HHL71800000-envelope-manifest-no-docs-ed25519.json` file is the same transfer but without any additional documents and no ebl visualization.  

`HHL71800000-envelope-manifest-rsa.json` is the same transfer but signed by EBL2 (rsa-eblplatform.example.com) and sent to itself - do not use this for transfer testing, unless you are testing self-transfers. The file can also be used for testing the rsa signed envelopes are handled correctly by the ebl verification code, since it is a valid envelope in all other respects.

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


