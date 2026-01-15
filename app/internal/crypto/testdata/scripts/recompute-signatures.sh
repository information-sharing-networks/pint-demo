#!/bin/bash
set -e
# script to calculate checksums and signatures for DCSA test data

# WARNING: you should not use this script unless you have made changes to the test data that require the signatures or checksums to be recomputed.
# It does cretate correct signatures, but it is not very convenient and - since the data has to be manually incorporated into the test data -  it is error prone.
#
# If you find yourself using it a lot, you should probably create some proper tooling to make it easier 
# (don't use the pint-demo packages - the signatures need to be created independently as this data is used in tests).

function usage() {
  echo "Usage: $0 -d <project_root_dir>"
  exit 1
}

function hash() {
     openssl dgst -sha256 -hex | awk '{print $2}'
}
function hash_json() {
    # canonicalize json, remove newlines, hash
    jq -c -S '.' | tr -d '\n' | hash
    if [ $? -ne 0 ]; then
        echo "Error: jq failed to canonicalize json"
        exit 1
    fi
}

# Extract kid from JWK file
function get_kid_from_jwk() {
    local jwk_file=$1
    jq -r '.keys[0].kid' < "$jwk_file"
    if [ $? -ne 0 ]; then
        echo "Error: failed to extract kid from JWK file: $jwk_file"
        exit 1
    fi
}

# Sign JSON and return the JWS string
# Uses JWK thumbprint-based kid
function sign_json_rsa() {
    local host=$1
    local kid=$(get_kid_from_jwk "$KEY_DIR/rsa-${host}.example.com.private.jwk")
    jq -c -S '.' | \
        tr -d '\n' | \
        step crypto jws sign \
            --key "$KEY_DIR/rsa-${host}.example.com.private.pem" \
            --alg RS256 \
            --kid "$kid" \
            --x5c-cert "$CERT_DIR/rsa-${host}.example.com-fullchain.crt"
    if [ $? -ne 0 ]; then
        echo "Error: failed to sign json"
        exit 1
    fi
}

function sign_json_ed25519() {
    local host=$1
    local kid=$(get_kid_from_jwk "$KEY_DIR/ed25519-${host}.example.com.private.jwk")
    jq -c -S '.' | \
        tr -d '\n' | \
        step crypto jws sign \
            --key "$KEY_DIR/ed25519-${host}.example.com.private.pem" \
            --alg EdDSA \
            --kid "$kid" \
            --x5c-cert "$CERT_DIR/ed25519-${host}.example.com-fullchain.crt"
    if [ $? -ne 0 ]; then
        echo "Error: failed to sign json"
        exit 1
    fi
}

# Sign JSON and return the SHA-256 hash of the JWS
function sign_and_hash_json_rsa() {
    local host=$1
    local kid=$(get_kid_from_jwk "$KEY_DIR/rsa-${host}.example.com.private.jwk")
    jq -c -S '.' | \
        tr -d '\n' | \
        step crypto jws sign \
            --key "$KEY_DIR/rsa-${host}.example.com.private.pem" \
            --alg RS256 \
            --kid "$kid"  \
            --x5c-cert "$CERT_DIR/rsa-${host}.example.com-fullchain.crt" | \
            tr -d '\n' | \
        hash
    if [ $? -ne 0 ]; then
        echo "Error: failed to sign and hash json"
        exit 1
    fi
}

function sign_and_hash_json_ed25519() {
    local host=$1
    local kid=$(get_kid_from_jwk "$KEY_DIR/ed25519-${host}.example.com.private.jwk")
    jq -c -S '.' | \
        tr -d '\n' | \
        step crypto jws sign \
            --key "$KEY_DIR/ed25519-${host}.example.com.private.pem" \
            --alg EdDSA \
            --kid "$kid" \
            --x5c-cert "$CERT_DIR/ed25519-${host}.example.com-fullchain.crt" | \
            tr -d '\n' | \
        hash
    if [ $? -ne 0 ]; then
        echo "Error: failed to sign and hash json"
        exit 1
    fi
}

#
# main
#

while getopts "d:h" o; do
  case ${o} in
    h) usage ;;
    d) PROJECT_ROOT_DIR="$OPTARG" ;;
    ?) usage ;;
  esac
done

#
# set up env
#

if [ -z "$PROJECT_ROOT_DIR" ]; then
    echo "test data dir not specified" >&2
    usage
fi

PATH="/opt/homebrew/opt/openssl@3/bin:$PATH" # v3.6 needed for ed25519 support
EXPIRY_DAYS=3650

PROJECT_ROOT_DIR=$(realpath $PROJECT_ROOT_DIR)

if [ -z "$PROJECT_ROOT_DIR" ]; then
  echo "test data dir not specified" >&2
  usage
fi

if [ ! -d "$PROJECT_ROOT_DIR" ]; then
    echo "could not open test data dir: $PROJECT_ROOT_DIR" >&2
    exit 1
fi 
TRANSPORT_DOCS_DIR="$PROJECT_ROOT_DIR/app/internal/crypto/testdata/transport-documents"
PINT_TRANSFERS_DIR="$PROJECT_ROOT_DIR/app/internal/crypto/testdata/pint-transfers"
KEY_DIR="$PROJECT_ROOT_DIR/app/internal/crypto/testdata/keys"
CERT_DIR="$PROJECT_ROOT_DIR/app/internal/crypto/testdata/certs"

# Check dependencies
for cmd in jq openssl step; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd is required but not installed"
        exit 1
    fi
done

# stage 1: compute base checksums
# These are checksums of raw files (transport document, PDFs) that don't depend on any signatures.
#
# MANUAL UPDATE REQUIRED AFTER THIS STAGE:
# - Update issuance-manifest.json with eBLVisualisationByCarrierChecksum (if applicable)
# - Update envelope-manifest-*.json files with transportDocumentChecksum and document metadata
# - Update transfer-chain-entry-*.json files with transportDocumentChecksum
#
function stage1() {
    # Calculate checksum for transport document json
    doc_file="$TRANSPORT_DOCS_DIR/HHL71800000-unsigned.json"
    checksum=$(jq '.document' < "$doc_file" | hash_json)

    echo "envelope-manifest, transfer-chain-entry"
    echo "transportDocumentChecksum: $checksum"
    echo
    echo ---

    # checksum for ebl visualization
    pdf_file="$TRANSPORT_DOCS_DIR/HHL71800000.pdf"
    pdf_checksum=$(hash < $pdf_file)
    pdf_size=$(wc -c < "$pdf_file" | tr -d ' ')

    echo "issuance-manifest"
    echo "eBLVisualisationByCarrierChecksum: $pdf_checksum"
    echo 
    echo ---

    echo "envelope-manifest"
    echo "eBLVisualisationByCarrier.name: HHL71800000.pdf"
    echo "eblVisualisationByCarrier.size: $pdf_size"
    echo "eBLVisualisationByCarrier.documentChecksum (envelope-manifest): $pdf_checksum"
    echo 
    echo ---

    # supporting docs  - invoice.pdf and packing-list.pdf

    pdf_file="$PINT_TRANSFERS_DIR/HHL71800000-invoice.pdf"
    pdf_checksum=$(hash < $pdf_file)
    pdf_size=$(wc -c < "$pdf_file" | tr -d ' ')
    echo "envelope-manifest"
    echo "supportingDocuments[0].name: HHL71800000-invoice.pdf"
    echo "supportingDocuments[0].size: $pdf_size"
    echo "supportingDocuments[0].documentChecksum: $pdf_checksum"
    echo
    echo ---


    pdf_file="$PINT_TRANSFERS_DIR/HHL71800000-packing-list.pdf"
    pdf_checksum=$(hash < $pdf_file)
    pdf_size=$(wc -c < "$pdf_file" | tr -d ' ')
    echo "envelope-manifest"
    echo "supportingDocuments[0].name: HHL71800000-packing-list.pdf"
    echo "supportingDocuments[0].size: $pdf_size"
    echo "supportingDocuments[0].documentChecksum: $pdf_checksum"
    echo 
    echo ---

}

# stage 2: compute issuance manifest signatures
# The issuance manifest is signed by the carrier and contains checksums from stage 1.
#
# MANUAL UPDATE REQUIRED AFTER THIS STAGE:
# - Update HHL71800000-issuance-manifest.json files (if needed)
# - Update transfer-chain-entry-ISSU-*.json files with the issuanceManifestSignedContent values below
#
function stage2() {
    # Ed25519 issuance manifest
    json_file="$TRANSPORT_DOCS_DIR/HHL71800000-issuance-manifest.json"
    jws=$(sign_json_ed25519 carrier < "$json_file")
    echo "UPDATE: issuance-manifest, transfer-chain-entry-ISSU-ed25519"
    echo "issuanceManifestSignedContent: " "$jws"
    echo ""
    echo "---"

    # RSA issuance manifest
    json_file="$TRANSPORT_DOCS_DIR/HHL71800000-issuance-manifest.json"
    jws=$(sign_json_rsa carrier < "$json_file")
    echo "UPDATE: issuance-manifest, transfer-chain-entry-ISSU-rsa"
    echo "issuanceManifestSignedContent: " "$jws"
    echo ""
    echo "---"
}

# stage 3: compute transfer chain entry checksums
# These are checksums of the signed transfer chain entries.
# The ISSU entries must already contain the issuanceManifestSignedContent from stage 2.
# The TRNS entries must already contain the previousEnvelopeTransferChainEntrySignedContentChecksum
# (which is the checksum of the signed ISSU entry computed in this stage).
#
# MANUAL UPDATE REQUIRED AFTER THIS STAGE:
# - Update transfer-chain-entry-TRNS-*.json files with previousEnvelopeTransferChainEntrySignedContentChecksum
# - Update envelope-manifest-*.json files with lastEnvelopeTransferChainEntrySignedContentChecksum
#
function stage3() {
    # Checksum of ISSU entry (for use in TRNS entry's previousEnvelopeTransferChainEntrySignedContentChecksum)
    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-ed25519.json"
    checksum=$(sign_and_hash_json_ed25519 eblplatform < "$json_file")
    echo "UPDATE: transfer-chain-entry-TRNS-ed25519.json"
    echo "previousEnvelopeTransferChainEntrySignedContentChecksum: $checksum"
    echo
    echo ---

    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-rsa.json"
    checksum=$(sign_and_hash_json_rsa eblplatform < "$json_file")
    echo "UPDATE: transfer-chain-entry-TRNS-rsa.json"
    echo "previousEnvelopeTransferChainEntrySignedContentChecksum: $checksum"
    echo
    echo ---


    # Checksum of TRNS entry (for use in envelope manifest's lastEnvelopeTransferChainEntrySignedContentChecksum)
    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-TRNS-ed25519.json"
    checksum=$(sign_and_hash_json_ed25519 eblplatform < "$json_file")
    echo "UPDATE: envelope-manifest-ed25519.json"
    echo "lastEnvelopeTransferChainEntrySignedContentChecksum: $checksum"
    echo
    echo ---

    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-TRNS-rsa.json"
    checksum=$(sign_and_hash_json_rsa eblplatform < "$json_file")
    echo "UPDATE: envelope-manifest-rsa.json"
    echo "lastEnvelopeTransferChainEntrySignedContentChecksum: $checksum"
    echo
    echo ---
 }

# stage 4: compute signatures for ebl envelope
# These are the final JWS signatures that go into the ebl envelope.
# The envelope manifest must already contain the lastEnvelopeTransferChainEntrySignedContentChecksum from stage 3.
#
# MANUAL UPDATE REQUIRED AFTER THIS STAGE:
# - Update ebl-envelope-*.json files with:
#   - envelopeTransferChain[0] (ISSU entry signature)
#   - envelopeTransferChain[1] (TRNS entry signature)
#   - envelopeManifestSignedContent
#
function stage4() {
    # Calculate signatures for transfer chain entries in ebl envelope
    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-ed25519.json"
    jws=$(sign_json_ed25519 eblplatform < "$json_file")
    echo "ebl-envelope-ed25519"
    echo "envelopeTransferChain[0]: $jws"
    echo 
    echo ---


    # ISSU entry (signed by eblplatform)
    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-ed25519.json"
    jws=$(sign_json_ed25519 eblplatform < "$json_file")
    echo ebl-envelope-ed25519
    echo "envelopeTransferChain[0]: " "$jws"
    echo ""
    echo "---"

    # TRNS entry (signed by eblplatform)
    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-TRNS-ed25519.json"
    jws=$(sign_json_ed25519 eblplatform < "$json_file")
    echo ebl-envelope-ed25519
    echo "envelopeTransferChain[1]: " "$jws"
    echo ""
    echo "---"

    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-rsa.json"
    jws=$(sign_json_rsa eblplatform < "$json_file")
    echo "ebl-envelope-rsa"
    echo "envelopeTransferChain[0]: $jws"
    echo ---

    # ISSU entry (signed by eblplatform)
    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-rsa.json"
    jws=$(sign_json_rsa eblplatform < "$json_file")
    echo ebl-envelope-rsa
    echo "envelopeTransferChain[1]: "  "$jws"
    echo ""
    echo "---"

    # TRNS entry (signed by eblplatform)
    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-TRNS-rsa.json"
    jws=$(sign_json_rsa eblplatform < "$json_file")
    echo ebl-envelope-rsa
    echo "envelopeTransferChain[1]: " "$jws"
    echo ""
    echo "---"

    # Ed25519 envelope manifest
    json_file="$PINT_TRANSFERS_DIR/HHL71800000-envelope-manifest-ed25519.json"
    jws=$(sign_json_ed25519 eblplatform < "$json_file")
    echo "ebl-envelope-ed25519"
    echo "envelopeManifestSignedContent:" "$jws"
    echo ""
    echo "---"

    # RSA envelope manifest
    json_file="$PINT_TRANSFERS_DIR/HHL71800000-envelope-manifest-rsa.json"
    jws=$(sign_json_rsa eblplatform < "$json_file")
    echo "ebl-envelope-rsa"
    echo "envelopeManifestSignedContent: " "$jws"
    echo ""
    echo "---"

}



# steps to run

echo "========================================="
echo "Stage 1: Compute base checksums"
echo "========================================="
stage1

read -p "Press enter to continue to stage 2"
clear

echo "========================================="
echo "Stage 2: Sign issuance manifests"
echo "========================================="
stage2

read -p "Press enter to continue to stage 3"
clear

echo "========================================="
echo "Stage 3: Compute transfer chain entry checksums"
echo "========================================="
stage3

read -p "Press enter to continue to stage 4"
clear

echo "========================================="
echo "Stage 4: Sign envelope components"
echo "========================================="
stage4

