# PINT Transfer Test Data

This directory contains test data for PINT

# todo
We should have:

Entry 1: ISSU transaction on WAVE (first entry, has issuanceManifestSignedContent)
Entry 2: TRNS transaction from WAVE to BOLE (has previousEnvelopeTransferChainEntrySignedContentChecksum)
Does this clarify why we need multiple entries? 🎯

the ISSU is the first entry, and the TRNS is the second entry.
because ISSU is the first transaction, it is the first entry in the transfer chain and must contain the issuanceManifestSignedContent. There are therefore two versions, one containing the issuanceManifestSignedContent that was signed with ed25519, and one signed with rsa. 



## Files

- `HHL71800000-transfer-ed25519.json` - PINT transfer test data using Ed25519 signatures
- `HHL71800000-transfer-rsa.json` - PINT transfer test data using RSA signatures
- `HHL71800000-invoice.pdf` - Example supporting document
- `HHL71800000-packing-list.pdf` - Example supporting document

the transport document JSON is in `../transport-documents/HHL71800000.json`
the transpoft document visualization is in `../transport-documents/HHL71800000.pdf`

# certs and keys
the transport doc was signed by `ed25519-carrier.example.com` and `rsa-carrier.example.com` respectively.
see `../transport-documents/certs` and `../transport-documents/keys`

the envelope manifest was signed by `ed25519-eblplatform.example.com` and `rsa-eblplatform.example.com` respectively.
see `certs/` and `keys/`


## Structure

Each test file contains:

1. **transportDocument**: The full transport document (copied from the corresponding issuance test file)
2. **issuanceManifestSignedContent**: The JWS from the issuance phase (links issuance to transfer)
3. **envelopeTransferChain**: Array of transfer chain entries, each containing:
   - **entry**: The unsigned transfer chain entry object:
     - `eblPlatform`: The platform code (WAVE, BOLE, etc.)
     - `transportDocumentChecksum`: SHA-256 of the canonicalized transport document
     - `issuanceManifestSignedContent`: Reference to the issuance manifest (first entry only)
     - `previousEnvelopeTransferChainEntrySignedContentChecksum`: SHA-256 of previous entry's JWS (subsequent entries)
     - `transactions`: Array of transactions (ISSU, TRNS, ENDORSE, etc.)
   - **signedContent**: JWS signature of the entry
4. **eBLVisualisationByCarrier**: Metadata for the eBL PDF visualization
5. **supportingDocuments**: Array of supporting document metadata (invoices, packing lists, etc.)
6. **envelopeManifestSignedContent**: JWS signature of the envelope manifest (what the test verifies)

### Transfer Chain Structure

The transfer chain demonstrates the complete lifecycle:

**Entry 1 (ISSU)**: Initial issuance
- Platform issues eBL to first holder
- Contains `issuanceManifestSignedContent` linking to issuance phase
- No `previousEnvelopeTransferChainEntrySignedContentChecksum` (it's the first entry)

**Entry 2 (TRNS)**: Transfer of possession
- Current holder transfers eBL to new holder
- Contains `previousEnvelopeTransferChainEntrySignedContentChecksum` linking to Entry 1
- May be cross-platform (WAVE → BOLE) or same-platform

Each entry is cryptographically signed, creating an unbreakable chain of custody.

## Relationship to Issuance Test Data

These files build upon the issuance test data in `../transport-documents/`:
- Same transport document (HHL71800000)
- References the issuance manifest from the issuance phase
- Uses the same eBL visualization PDF
- Demonstrates the complete flow: Issuance → Transfer

## Keys and Certificates

Uses shared keys and certificates from:
- `../keys/` - Private keys for signing
- `../certs/` - Certificate chains for x5c headers

**Key roles:**
- `ed25519-carrier.example.com` / `rsa-carrier.example.com` - Used for issuance
- `ed25519-eblplatform.example.com` / `rsa-eblplatform.example.com` - Used for PINT transfers

## Regenerating Test Data

These files contain placeholder values that need to be regenerated with proper cryptographic signatures.

To regenerate:
1. Load the transport document from the issuance test file
2. Calculate the transport document checksum
3. Create and sign the transfer chain entry
4. Calculate checksums for supporting documents
5. Build and sign the envelope manifest
6. Update this file with the generated values

See `TestRecreateSampleEnvelopeManifestEd25519` and `TestRecreateSampleEnvelopeManifestRSA` in `envelope_test.go` for the implementation.

## DCSA Specification

Based on DCSA EBL_PINT v3.0.0 specification.

Key concepts:
- **Envelope Manifest**: Contains checksums of transport document and last transfer chain entry
- **Transfer Chain**: Ordered list of signed entries tracking the eBL's history
- **Non-repudiation**: Each entry is cryptographically signed, creating an unbreakable chain of custody

