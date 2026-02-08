#!/bin/bash
set -e
# script to calculate checksums and signatures for DCSA test data

# If you find yourself using it a lot, you should probably create some proper tooling to make it easier 
# (don't use the pint-demo packages - the signatures need to be created independently as this data is used in tests).

function usage() {
  echo
  echo "Usage: $0 -d <project_root_dir> "
  echo 
  echo " this script recomputes signatures and checksums in the test data"
  echo " and updates the test envelope files with recomputed signatures and checksums"

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
    echo "project dir not specified" >&2
    usage
fi

PATH="/opt/homebrew/opt/openssl@3/bin:$PATH" # v3.6 needed for ed25519 support
EXPIRY_DAYS=3650

PROJECT_ROOT_DIR=$(realpath $PROJECT_ROOT_DIR)

if [ -z "$PROJECT_ROOT_DIR" ]; then
  echo "project dir not specified" >&2
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
# This stage automatically updates the manifest files with the computed checksums.
#
function stage1() {
    echo "Computing base checksums..."
    echo

    # Calculate checksum for transport document json
    doc_file="$TRANSPORT_DOCS_DIR/HHL71800000-unsigned.json"
    transport_doc_checksum=$(jq '.document' < "$doc_file" | hash_json)

    echo "✓ transportDocumentChecksum: $transport_doc_checksum"

    # Update envelope manifests with transport document checksum
    for manifest in "$PINT_TRANSFERS_DIR/HHL71800000-envelope-manifest-ed25519.json" \
                    "$PINT_TRANSFERS_DIR/HHL71800000-envelope-manifest-rsa.json" \
                    "$PINT_TRANSFERS_DIR/HHL71800000-envelope-manifest-no-docs-ed25519.json"; do
        jq --arg checksum "$transport_doc_checksum" \
           '.transportDocumentChecksum = $checksum' \
           "$manifest" > "$manifest.tmp" && mv "$manifest.tmp" "$manifest"
        echo "  Updated: $(basename $manifest)"
    done

    # Update transfer chain entries with transport document checksum
    for entry in "$PINT_TRANSFERS_DIR"/HHL71800000-transfer-chain-entry-*.json; do
        jq --arg checksum "$transport_doc_checksum" \
           '.transportDocumentChecksum = $checksum' \
           "$entry" > "$entry.tmp" && mv "$entry.tmp" "$entry"
        echo "  Updated: $(basename $entry)"
    done

    echo
    echo "Note: Stage 1 does NOT update eBL visualization or supporting document metadata."
    echo "Those are already correct in the envelope manifests and don't need recomputation."
    echo

}

# stage 2: compute issuance manifest signatures
# The issuance manifest is signed by the carrier and contains checksums from stage 1.
# This stage automatically updates the transfer chain ISSU entries with the signed manifests.
#
function stage2() {
    echo "Signing issuance manifests..."
    echo

    # Ed25519 issuance manifest
    json_file="$TRANSPORT_DOCS_DIR/HHL71800000-issuance-manifest.json"
    jws_ed25519=$(sign_json_ed25519 carrier < "$json_file")
    echo "✓ Ed25519 issuanceManifestSignedContent generated"

    # Update ISSU entry with Ed25519 signature
    issu_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-ed25519.json"
    jq --arg jws "$jws_ed25519" \
       '.issuanceManifestSignedContent = $jws' \
       "$issu_file" > "$issu_file.tmp" && mv "$issu_file.tmp" "$issu_file"
    echo "  Updated: $(basename $issu_file)"
    echo

    # RSA issuance manifest
    jws_rsa=$(sign_json_rsa carrier < "$json_file")
    echo "✓ RSA issuanceManifestSignedContent generated"

    # Update ISSU entry with RSA signature
    issu_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-rsa.json"
    jq --arg jws "$jws_rsa" \
       '.issuanceManifestSignedContent = $jws' \
       "$issu_file" > "$issu_file.tmp" && mv "$issu_file.tmp" "$issu_file"
    echo "  Updated: $(basename $issu_file)"
    echo
}

# stage 3: compute transfer chain entry checksums
# These are checksums of the signed transfer chain entries.
# The ISSU entries must already contain the issuanceManifestSignedContent from stage 2.
# This stage automatically updates TRNS entries and envelope manifests with the computed checksums.
#
function stage3() {
    echo "Computing transfer chain entry checksums..."
    echo

    # Checksum of ISSU entry (for use in TRNS entry's previousEnvelopeTransferChainEntrySignedContentChecksum)
    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-ed25519.json"
    issu_checksum_ed25519=$(sign_and_hash_json_ed25519 eblplatform < "$json_file")
    echo "✓ ISSU-ed25519 checksum: $issu_checksum_ed25519"

    # Update TRNS entry with previous checksum
    trns_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-TRNS-ed25519.json"
    jq --arg checksum "$issu_checksum_ed25519" \
       '.previousEnvelopeTransferChainEntrySignedContentChecksum = $checksum' \
       "$trns_file" > "$trns_file.tmp" && mv "$trns_file.tmp" "$trns_file"
    echo "  Updated: $(basename $trns_file)"
    echo

    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-rsa.json"
    issu_checksum_rsa=$(sign_and_hash_json_rsa eblplatform < "$json_file")
    echo "✓ ISSU-rsa checksum: $issu_checksum_rsa"

    # Update TRNS entry with previous checksum
    trns_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-TRNS-rsa.json"
    jq --arg checksum "$issu_checksum_rsa" \
       '.previousEnvelopeTransferChainEntrySignedContentChecksum = $checksum' \
       "$trns_file" > "$trns_file.tmp" && mv "$trns_file.tmp" "$trns_file"
    echo "  Updated: $(basename $trns_file)"
    echo

    # Checksum of TRNS entry (for use in envelope manifest's lastEnvelopeTransferChainEntrySignedContentChecksum)
    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-TRNS-ed25519.json"
    trns_checksum_ed25519=$(sign_and_hash_json_ed25519 eblplatform < "$json_file")
    echo "✓ TRNS-ed25519 checksum: $trns_checksum_ed25519"

    # Update envelope manifests with last chain entry checksum
    for manifest in "$PINT_TRANSFERS_DIR/HHL71800000-envelope-manifest-ed25519.json" \
                    "$PINT_TRANSFERS_DIR/HHL71800000-envelope-manifest-no-docs-ed25519.json"; do
        jq --arg checksum "$trns_checksum_ed25519" \
           '.lastEnvelopeTransferChainEntrySignedContentChecksum = $checksum' \
           "$manifest" > "$manifest.tmp" && mv "$manifest.tmp" "$manifest"
        echo "  Updated: $(basename $manifest)"
    done
    echo

    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-TRNS-rsa.json"
    trns_checksum_rsa=$(sign_and_hash_json_rsa eblplatform < "$json_file")
    echo "✓ TRNS-rsa checksum: $trns_checksum_rsa"

    # Update envelope manifest with last chain entry checksum
    manifest="$PINT_TRANSFERS_DIR/HHL71800000-envelope-manifest-rsa.json"
    jq --arg checksum "$trns_checksum_rsa" \
       '.lastEnvelopeTransferChainEntrySignedContentChecksum = $checksum' \
       "$manifest" > "$manifest.tmp" && mv "$manifest.tmp" "$manifest"
    echo "  Updated: $(basename $manifest)"
    echo
 }

# stage 4: compute signatures for ebl envelope
# These are the final JWS signatures that go into the ebl envelope.
# The envelope manifest must already contain the lastEnvelopeTransferChainEntrySignedContentChecksum from stage 3.
# This stage automatically updates the envelope files with all the signed content.
#
function stage4() {
    echo "Signing envelope components..."
    echo

    # Ed25519 envelope
    echo "Processing ebl-envelope-ed25519.json..."

    # ISSU entry (signed by eblplatform)
    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-ed25519.json"
    issu_jws=$(sign_json_ed25519 eblplatform < "$json_file")
    echo "  ✓ Signed ISSU entry"

    # TRNS entry (signed by eblplatform)
    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-TRNS-ed25519.json"
    trns_jws=$(sign_json_ed25519 eblplatform < "$json_file")
    echo "  ✓ Signed TRNS entry"

    # Envelope manifest
    json_file="$PINT_TRANSFERS_DIR/HHL71800000-envelope-manifest-ed25519.json"
    manifest_jws=$(sign_json_ed25519 eblplatform < "$json_file")
    echo "  ✓ Signed envelope manifest"

    # Update envelope file
    envelope_file="$PINT_TRANSFERS_DIR/HHL71800000-ebl-envelope-ed25519.json"
    jq --arg issu "$issu_jws" --arg trns "$trns_jws" --arg manifest "$manifest_jws" \
       '.envelopeTransferChain[0] = $issu | .envelopeTransferChain[1] = $trns | .envelopeManifestSignedContent = $manifest' \
       "$envelope_file" > "$envelope_file.tmp" && mv "$envelope_file.tmp" "$envelope_file"
    echo "  Updated: $(basename $envelope_file)"
    echo

    # RSA envelope
    echo "Processing ebl-envelope-rsa.json..."

    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-rsa.json"
    issu_jws=$(sign_json_rsa eblplatform < "$json_file")
    echo "  ✓ Signed ISSU entry"

    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-TRNS-rsa.json"
    trns_jws=$(sign_json_rsa eblplatform < "$json_file")
    echo "  ✓ Signed TRNS entry"

    json_file="$PINT_TRANSFERS_DIR/HHL71800000-envelope-manifest-rsa.json"
    manifest_jws=$(sign_json_rsa eblplatform < "$json_file")
    echo "  ✓ Signed envelope manifest"

    # Update envelope file
    envelope_file="$PINT_TRANSFERS_DIR/HHL71800000-ebl-envelope-rsa.json"
    jq --arg issu "$issu_jws" --arg trns "$trns_jws" --arg manifest "$manifest_jws" \
       '.envelopeTransferChain[0] = $issu | .envelopeTransferChain[1] = $trns | .envelopeManifestSignedContent = $manifest' \
       "$envelope_file" > "$envelope_file.tmp" && mv "$envelope_file.tmp" "$envelope_file"
    echo "  Updated: $(basename $envelope_file)"
    echo

    # Ed25519 no-docs envelope
    echo "Processing ebl-envelope-nodocs-ed25519.json..."

    # Reuse the same ISSU and TRNS signatures from ed25519 envelope
    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-ISSU-ed25519.json"
    issu_jws=$(sign_json_ed25519 eblplatform < "$json_file")
    echo "  ✓ Signed ISSU entry"

    json_file="$PINT_TRANSFERS_DIR/HHL71800000-transfer-chain-entry-TRNS-ed25519.json"
    trns_jws=$(sign_json_ed25519 eblplatform < "$json_file")
    echo "  ✓ Signed TRNS entry"

    # Sign the no-docs manifest
    json_file="$PINT_TRANSFERS_DIR/HHL71800000-envelope-manifest-no-docs-ed25519.json"
    manifest_jws=$(sign_json_ed25519 eblplatform < "$json_file")
    echo "  ✓ Signed no-docs envelope manifest"

    # Update envelope file
    envelope_file="$PINT_TRANSFERS_DIR/HHL71800000-ebl-envelope-nodocs-ed25519.json"
    jq --arg issu "$issu_jws" --arg trns "$trns_jws" --arg manifest "$manifest_jws" \
       '.envelopeTransferChain[0] = $issu | .envelopeTransferChain[1] = $trns | .envelopeManifestSignedContent = $manifest' \
       "$envelope_file" > "$envelope_file.tmp" && mv "$envelope_file.tmp" "$envelope_file"
    echo "  Updated: $(basename $envelope_file)"
    echo

}


# steps to run


echo "========================================="
echo "Stage 1: Compute base checksums"
echo "========================================="
stage1

echo "========================================="
echo "Stage 2: Sign issuance manifests"
echo "========================================="
stage2

echo "========================================="
echo "Stage 3: Compute transfer chain entry checksums"
echo "========================================="
stage3

echo "========================================="
echo "Stage 4: Sign envelope components"
echo "========================================="
stage4