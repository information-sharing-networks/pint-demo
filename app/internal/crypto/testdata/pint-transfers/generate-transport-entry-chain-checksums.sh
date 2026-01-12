#!/bin/bash
set -e

# script to calculate checksums for PINT transfer entry chain test data
SCRIPT_DIR="$(pwd)"
TRANSPORT_DOCS_DIR="$SCRIPT_DIR/../transport-documents"
PINT_TRANSFERS_DIR="$SCRIPT_DIR"
KEY_DIR="$SCRIPT_DIR/../keys"

# Verify we're in the right directory
if [ ! -f "HHL71800000-transfer-chain-entry-ISSU-eb25519.json" ]; then
    echo "Error: Must run from pint-transfers directory"
    exit 1
fi

# Check dependencies
for cmd in jq openssl; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd is required but not installed"
        exit 1
    fi
done



function hash() {
     openssl dgst -sha256 -hex | awk '{print $2}'
}
function hash_json() {
    # canonicalize json, remove newlines, hash
    jq -c -S '.' | tr -d '\n' | hash
}

# Sign JSON and return the JWS string
function sign_json_rsa() {
    host=$1
    jq -c -S '.' | \
        tr -d '\n' | \
        step crypto jws sign \
            --key $KEY_DIR/rsa-${host}.example.com.private.pem \
            --alg RS256
}

function sign_json_ed25519() {
    host=$1
    jq -c -S '.' | \
        tr -d '\n' | \
        step crypto jws sign \
            --key $KEY_DIR/ed25519-${host}.example.com.private.pem \
            --alg EdDSA
}

# Sign JSON and return the SHA-256 hash of the JWS
function sign_and_hash_json_rsa() {
    host=$1
    jq -c -S '.' | \
        tr -d '\n' | \
        step crypto jws sign \
            --key $KEY_DIR/rsa-${host}.example.com.private.pem \
            --alg RS256 | \
        hash
}

function sign_and_hash_json_ed25519() {
    host=$1
    jq -c -S '.' | \
        tr -d '\n' | \
        step crypto jws sign \
            --key $KEY_DIR/ed25519-${host}.example.com.private.pem \
            --alg EdDSA | \
        hash
}


#
# main
#

# Calculate checksum for transport document json
doc_file="$TRANSPORT_DOCS_DIR/HHL71800000-unsigned.json"

checksum=$(jq '.document' < "$doc_file" | hash_json)

echo "Transport Document JSON Checksum ($doc_file): $checksum"
echo
echo ---

pdf_file="$TRANSPORT_DOCS_DIR/HHL71800000.pdf"
# get document field and hash
pdf_checksum=$(hash < $pdf_file)
pdf_size=$(wc -c < "$pdf_file" | tr -d ' ')

echo "File: HHL71800000.pdf"
echo "Size: $pdf_size bytes"
echo "eBLVisualisationByCarrierChecksum: $pdf_checksum"
echo 
echo ---


# supporting docs  - invoice.pdf and packing-list.pdf

pdf_file="$PINT_TRANSFERS_DIR/HHL71800000-invoice.pdf"
pdf_checksum=$(hash < $pdf_file)
pdf_size=$(wc -c < "$pdf_file" | tr -d ' ')
echo "SupportingDoc[0]: HHL71800000-invoice.pdf"
echo "Size: $pdf_size bytes"
echo "Supporting Document Checksum: $pdf_checksum"
echo
echo ---


pdf_file="$PINT_TRANSFERS_DIR/HHL71800000-packing-list.pdf"
pdf_checksum=$(hash < $pdf_file)
pdf_size=$(wc -c < "$pdf_file" | tr -d ' ')
echo "SupportingDoc[1]: HHL71800000-packing-list.pdf"
echo "Size: $pdf_size bytes"
echo "Supporting Document Checksum: $pdf_checksum"
echo 
echo ---

# Calculate checksum for transfer chain entries
json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-eb25519.json"
checksum=$(hash_json < "$json_file")
echo "Transfer Chain Entry [0] (ISSU) Checksum - ed25519 ($json_file): $checksum"
echo 
echo ---

json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-rsa.json"  
checksum=$(hash_json < "$json_file")
echo "Transfer Chain Entry [0] (ISSU) Checksum - rsa ($json_file): $checksum"
echo 
echo ---

# previous envelope transfer chain entry signed content checksum
json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-eb25519.json"
checksum=$(sign_and_hash_json_ed25519 carrier < "$json_file")
echo "previousEnvelopeTransferChainEntrySignedContentChecksum - ed25519 ($json_file): $checksum"
echo 
echo ---


json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-rsa.json"
checksum=$(sign_and_hash_json_rsa carrier < "$json_file")
echo "previousEnvelopeTransferChainEntrySignedContentChecksum - rsa ($json_file): $checksum"
echo 
echo ---


# last envelope transfer chain entry signed content checksum
json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-TRNS-eb25519.json"
checksum=$(sign_and_hash_json_ed25519 eblplatform < "$json_file")
echo "lastEnvelopeTransferChainEntrySignedContentChecksum - ed25519 ($json_file): $checksum"
echo 
echo ---

json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-TRNS-rsa.json"
checksum=$(sign_and_hash_json_rsa eblplatform < "$json_file")           
echo "lastEnvelopeTransferChainEntrySignedContentChecksum - rsa ($json_file): $checksum"
echo 
echo ---


# ISSU entry (signed by carrier)
json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-eb25519.json"
issu_jws_ed25519=$(sign_json_ed25519 carrier < "$json_file")
echo "envelopeTransferChain[0] (ISSU - Ed25519):"
echo "$issu_jws_ed25519"
echo ""
echo "---"

# TRNS entry (signed by eblplatform)
json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-TRNS-eb25519.json"
trns_jws_ed25519=$(sign_json_ed25519 eblplatform < "$json_file")
echo "envelopeTransferChain[1] (TRNS - Ed25519):"
echo "$trns_jws_ed25519"
echo ""
echo "---"

# ISSU entry (signed by carrier)
json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-rsa.json"
issu_jws_rsa=$(sign_json_rsa carrier < "$json_file")
echo "envelopeTransferChain[0] (ISSU - RSA):"
echo "$issu_jws_rsa"
echo ""
echo "---"

# TRNS entry (signed by eblplatform)
json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-TRNS-rsa.json"
trns_jws_rsa=$(sign_json_rsa eblplatform < "$json_file")
echo "envelopeTransferChain[1] (TRNS - RSA):"
echo "$trns_jws_rsa"
echo ""
echo "---"


# Ed25519 envelope manifest
json_file="$PINT_TRANSFERS_DIR/HHL71800000-EnvelopeManifest-eb25519.json"
manifest_jws_ed25519=$(sign_json_ed25519 eblplatform < "$json_file")
echo "envelopeManifestSignedContent (Ed25519):"
echo "$manifest_jws_ed25519"
echo ""
echo "---"

# RSA envelope manifest
json_file="$PINT_TRANSFERS_DIR/HHL71800000-EnvelopeManifest-rsa.json"
manifest_jws_rsa=$(sign_json_rsa eblplatform < "$json_file")
echo "envelopeManifestSignedContent (RSA):"
echo "$manifest_jws_rsa"
echo ""
echo "---"