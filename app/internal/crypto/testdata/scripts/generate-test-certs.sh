#!/bin/bash

# make the certs needed to test pint-demo
set -e

function usage() {
  echo "Usage: $0 -d <certs_dir>"
  exit 1
}

function create_self_signed_cert() {
    local filename=$1
    local O=$2
    local CN=$3
    openssl req -x509 -newkey ed25519 -nodes \
        -keyout "$CERTS_DIR/${filename}.key" \
        -out "$CERTS_DIR/${filename}.crt" \
        -days $EXPIRY_DAYS \
        -subj "/C=GB/ST=England/L=London/O=${O}/CN=${CN}"
}

function create_signing_request() {    
    local filename=$1
    local O=$2
    local CN=$3
    openssl req -newkey ed25519 -nodes \
        -keyout "$CERTS_DIR/${filename}.key" \
        -out "$CERTS_DIR/${filename}.csr" \
        -subj "/C=GB/ST=England/L=London/O=${O}/CN=${CN}"
}   

function sign_intermediate_certificate() {

    local ca=$1
    local cert=$2
    openssl x509 -req -in "$CERTS_DIR/${cert}.csr" \
        -CA "$CERTS_DIR/${ca}.crt" \
        -CAkey "$CERTS_DIR/${ca}.key" \
        -CAcreateserial \
        -out "$CERTS_DIR/${cert}.crt" \
        -days $EXPIRY_DAYS \
        -extfile <(echo "basicConstraints=CA:TRUE")  # mark as CA so it can sign other certs
}

function sign_leaf_certificate() {
    local ca=$1
    local cert=$2
    openssl x509 -req -in "$CERTS_DIR/${cert}.csr" \
        -CA "$CERTS_DIR/${ca}.crt" \
        -CAkey "$CERTS_DIR/${ca}.key" \
        -CAcreateserial \
        -out "$CERTS_DIR/${cert}.crt" \
        -days $EXPIRY_DAYS
}   

# note the expiry days - wait 1 day before using in test
function sign_expired_leaf_certificate() {
    local ca=$1 
    local cert=$2               
    openssl x509 -req -in "$CERTS_DIR/${cert}.csr" \
        -CA "$CERTS_DIR/${ca}.crt" \
        -CAkey "$CERTS_DIR/${ca}.key" \
        -CAcreateserial \
        -out "$CERTS_DIR/${cert}.crt" \
        -days 1
}


# main

PATH="/opt/homebrew/opt/openssl@3/bin:$PATH" # v3.6 needed for ed25519 support
EXPIRY_DAYS=3650


while getopts "d:h" o; do
  case ${o} in
    h) usage ;;
    d) CERTS_DIR="$OPTARG" ;;
    ?) usage ;;
  esac
done

if [ -z "$CERTS_DIR" ]; then
  usage
fi

if [ ! -d "$CERTS_DIR" ]; then
    echo "could not open $CERTS_DIR" >&2
    exit 1
fi  


echo "1. Generating self-signed certificate  (self-signed.example.com)..."

create_self_signed_cert "self-signed" "Test BL Platform" "self-signed.example.com"

echo -e "\n2. Generating valid certificate chain ..."

echo -e "\n  Creating Root CA..."
create_self_signed_cert "root-ca" "Test Root CA Ltd" "Test Root CA" 

echo -e "\n   Creating Intermediate CA signing request..."
create_signing_request "intermediate-ca" "Test Intermediate CA Ltd" "Test Intermediate CA"


echo -e "\n   Signing Intermediate CA..."
sign_intermediate_certificate root-ca intermediate-ca 

echo -e "\n   Creating valid server leaf certificate (valid.example.com)..."
create_signing_request "valid-server" "Test BL Platform" "valid.example.com"


echo -e "\n   Signing valid server leaf certificate..."
sign_leaf_certificate intermediate-ca valid-server

echo -e "\n   Creating full chain file... (valid-fullchain.crt)"
cat "$CERTS_DIR/valid-server.crt" "$CERTS_DIR/intermediate-ca.crt" "$CERTS_DIR/root-ca.crt" > "$CERTS_DIR/valid-fullchain.crt"

echo -e "\n3. Generating expired certificate, (expired.example.com)..."

echo -e "\n   Creating expired server leaf certificate signing request..."
create_signing_request "expired-server" "Test BL Platform" "expired.example.com"

echo -e "\n   Signing expired server leaf certificate..."
sign_expired_leaf_certificate intermediate-ca expired-server    

echo -e "\n   Creating expired full chain file (expired-fullchain.crt)..."   
cat "$CERTS_DIR/expired-server.crt" "$CERTS_DIR/intermediate-ca.crt" "$CERTS_DIR/root-ca.crt" > "$CERTS_DIR/expired-fullchain.crt"

echo -e "\n4. Generating invalid certificate chain ..."

echo -e "\n   Creating untrusted CA..."
create_self_signed_cert "untrusted-ca" "Untrusted CA Ltd" "Untrusted Test CA"

echo -e "\n   Creating server leaf cert signed by untrusted CA (invalid-chain.example.com)..."
create_signing_request "invalid-chain-server" "Test BL Platform" "invalid-chain.example.com"

echo -e "\n   Signing server leaf cert signed by untrusted CA..."
sign_leaf_certificate untrusted-ca invalid-chain-server

echo -e "\n   Creating invalid chain file (invalid-chain-fullchain.crt)..."
cat "$CERTS_DIR/invalid-chain-server.crt" "$CERTS_DIR/intermediate-ca.crt" "$CERTS_DIR/root-ca.crt" > "$CERTS_DIR/invalid-chain-fullchain.crt"

echo -e "\n   Cleaning up temporary files..."
rm -f "$CERTS_DIR"/*.csr "$CERTS_DIR"/*.srl

echo
echo "done - certs generated in $CERTS_DIR"