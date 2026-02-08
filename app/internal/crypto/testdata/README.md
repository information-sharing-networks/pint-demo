# Test Data for Crypto Package

## Platform Registry

The `platform-registry.csv` file contains a test registry of platforms for use in testing the crypto package.

the servers used in testing are:
- EBL1: ed25519-eblplatform.example.com (uses ed25519 keys)
- EBL2: rsa-eblplatform.example.com (uses rsa keys)
- Carrier: ed25519-carrier.example.com

## Transport Documents
the `transport-documents` directory contains sample JSON that would be used in a issuance request. 

The computed fields (JWS and checksums) were calculated indepenently of the pint-demo code so they can be used in testing.

## PINT Transfers
The `pint-transfers` directory contains json that can be used in a PINT transfer.  The json is based on the DCSA openapi v3.0.0 PINT sample data.

**`HHL71800000-ebl-envelope-ed25519.json`** is the main file for the end-2-end tests of PINT transfers.

The ebl envelope requires that 2 supporting docs (`HHL71800000-invoice.pdf` nd `HHL71800000-packing-list.pdf`) + an ebl visualization (`HHL71800000.pdf`) be uploaded.
See enelope-manifest.json for the expected checksums and metadata. 

The transfer chain includes 2 entries:
- the first (created from `HHL71800000-transfer-chain-entry-ISSU-ed25519.json`) is the issuance entry (signed by the carrier and sent to EBL1) 
- the second (`HHL71800000-transfer-chain-entry-TRNS-ed25519.json`) is a transfer entry (signed by EBL1 and sent to EBL2).

the `HHL71800000-envelope-manifest-no-docs-ed25519.json` file is the same transport document but with no supporting documents and no ebl visualization.  

`HHL71800000-envelope-manifest-rsa.json` is the same transport document but issued to EBL2 and then transfered to EBL1 

## Test Certificates and Keys

The `certs/` and `keys/` directories contain test certificates and key pairs for use in testing the crypto package. 

The keys used to sign the valid issuance and PINT transfers are:
- `../keys/ed25519-carrier.example.com.private.jwk` 
- `../keys/ed25519-eblplatform.example.com.private.jwk` 
- `../keys/rsa-eblplatform.example.com.private.jwk`

The fullchain certs are included in the JWS headers:
- `../certs/ed25519-eblplatform.example.com-fullchain.crt` 
- `../certs/rsa-eblplatform.example.com-fullchain.crt`
- `../certs/ed25519-carrier.example.com-fullchain.crt`

The leaf certificates were created with Subject.Organization fields to simulate EV/OV certificates.  The Root and Intermediate CAs are self-signed:
- `../certs/root-ca.crt`
- `../certs/intermediate-ca.crt`

There are sample expired and invalid certificates for testing.

**Certificates expire in 10 years** (except the expired cert which expires 1 day after generation)

- **All leaf certificates** have matching JWK and PEM key pairs (same cryptographic key in different formats)

If you regenerate the keys and/or certificates, you will need to regenerate the signatures in the sample data (see below)

### Regenerating Test Keys and Certificates

The `scripts/` directory contains scripts to generate the test certificates and keys.  You should not need to run these scripts unless you need to regenerate the test keys and certificates.

**Note**  regenerating the keys and certificates will cause the existing sample data to fail tests until the signatures are recomputed. The tests **should** all rely on the data from the testdata directory, but you will need to double check for any hard-coded values.

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

the script will replace the signed content and manifests in the existing ebl envelope files.  It will not create new files.
if you alter the json content in the sample data, you will need to regenerate the signatures and checksums.

