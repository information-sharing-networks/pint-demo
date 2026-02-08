package testutil

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

// DecodeJWSPayload decodes the payload from a JWS string (header.payload.signature)
func DecodeJWSPayload(jws string) (map[string]any, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWS format: expected 3 parts, got %d", len(parts))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}

	return payload, nil
}

// LoadTestRootCA loads a root CA certificate from a PEM file and returns a cert pool
func LoadTestRootCA(certPath string) (*x509.CertPool, error) {
	certChain, err := crypto.ReadCertChainFromPEMFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read test certificate chain: %v", err)
	}

	if len(certChain) == 0 {
		return nil, fmt.Errorf("empty certificate chain")
	}

	// Create a root cert pool containing the test root CA
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(certChain[0]) // the root CA is the only cert in root-ca.pem
	return rootCAs, nil
}
