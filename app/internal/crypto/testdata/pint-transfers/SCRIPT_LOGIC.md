# Script Logic Review: generate-transport-entry-chain-checksums.sh

## Purpose
Generate all checksums and JWS signatures needed for PINT transfer test data.

## Key Functions

### 1. `hash()`
- Calculates SHA-256 hash of binary input
- Used for PDF files

### 2. `hash_json()`
- Canonicalizes JSON (sorts keys, removes whitespace)
- Calculates SHA-256 hash
- Used for JSON checksums (transport document, transfer chain entries)

### 3. `sign_json_rsa(host)` and `sign_json_ed25519(host)`
- **NEW**: Returns the actual JWS string
- Used for `envelopeTransferChain[]` and `envelopeManifestSignedContent`
- Takes hostname parameter to select the correct private key

### 4. `sign_and_hash_json_rsa(host)` and `sign_and_hash_json_ed25519(host)`
- Signs JSON and returns SHA-256 hash of the JWS
- Used for `previousEnvelopeTransferChainEntrySignedContentChecksum` and `lastEnvelopeTransferChainEntrySignedContentChecksum`

## Script Flow

### Phase 1: Document Checksums (Lines 73-121)
1. Transport document JSON checksum
2. eBL visualization PDF checksum + size
3. Supporting documents (invoice, packing list) checksums + sizes

### Phase 2: Transfer Chain Entry Checksums (Lines 123-151)
1. ISSU entry JSON checksums (unsigned)
2. ISSU entry JWS checksums (signed by carrier) → for `previousEnvelopeTransferChainEntrySignedContentChecksum`
3. TRNS entry JWS checksums (signed by eblplatform) → for `lastEnvelopeTransferChainEntrySignedContentChecksum`

### Phase 3: Envelope Transfer Chain JWS Strings (Lines 153-199)
**NEW SECTION**
1. ISSU entry JWS (Ed25519) - signed by carrier
2. TRNS entry JWS (Ed25519) - signed by eblplatform
3. ISSU entry JWS (RSA) - signed by carrier
4. TRNS entry JWS (RSA) - signed by eblplatform

These are the actual JWS strings to paste into `eblEnvelope.envelopeTransferChain[]`

### Phase 4: Envelope Manifest JWS Strings (Lines 201-225)
**NEW SECTION**
1. EnvelopeManifest JWS (Ed25519) - signed by eblplatform
2. EnvelopeManifest JWS (RSA) - signed by eblplatform

These are the actual JWS strings to paste into `eblEnvelope.envelopeManifestSignedContent`

## Key Signing Logic

| What | Signed By | Key Used | Output Type |
|------|-----------|----------|-------------|
| ISSU transfer chain entry | Carrier | `carrier.example.com` | JWS string |
| TRNS transfer chain entry | eBL Platform | `eblplatform.example.com` | JWS string |
| EnvelopeManifest | eBL Platform | `eblplatform.example.com` | JWS string |

## Checksums vs JWS Strings

**Important distinction:**
- `previousEnvelopeTransferChainEntrySignedContentChecksum` = SHA-256 hash of ISSU JWS
- `lastEnvelopeTransferChainEntrySignedContentChecksum` = SHA-256 hash of TRNS JWS
- `envelopeTransferChain[0]` = Actual ISSU JWS string (not a hash!)
- `envelopeTransferChain[1]` = Actual TRNS JWS string (not a hash!)
- `envelopeManifestSignedContent` = Actual EnvelopeManifest JWS string (not a hash!)

## Usage

```bash
cd app/internal/crypto/testdata/pint-transfers
./generate-transport-entry-chain-checksums.sh
```

The script outputs all values needed to complete the test data files.

