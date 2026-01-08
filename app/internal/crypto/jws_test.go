package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

func TestParseHeader(t *testing.T) {
	// { "alg": "HS256", "typ": "JWT" } (unexpected header: typ)
	invalidJwsString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"

	header, err := ParseHeader(invalidJwsString)
	if err == nil {
		t.Errorf("ParseHeader failed to reject an invalid header - got: %v", header)
	}
}

func TestSignAndVerifSignatureEdSCA(t *testing.T) {

	validEd25519PrivateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("could not create ed25519 key: %v", err)
	}
	validEd25519publicKey := validEd25519PrivateKey.Public().(ed25519.PublicKey)

	invalidEd25519PrivateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("could not create ed25519 key: %v", err)
	}
	invalidEd25519publicKey := invalidEd25519PrivateKey.Public().(ed25519.PublicKey)

	if err != nil {
		t.Fatalf("could not create RSA key: %v", err)
	}

	payload := []byte(`{ "message": "Hello, World!" }`)

	keyID := "12345"

	tests := []struct {
		name          string
		privateKey    ed25519.PrivateKey
		publicKey     ed25519.PublicKey
		keyID         string
		payload       []byte
		wantSignErr   bool
		wantVerifyErr bool
	}{
		{
			name:          "valid signature (Ed25519)",
			privateKey:    validEd25519PrivateKey,
			publicKey:     validEd25519publicKey,
			keyID:         keyID,
			payload:       payload,
			wantSignErr:   false,
			wantVerifyErr: false,
		},
		{
			name:          "invalid publicKey (Ed25519)",
			privateKey:    validEd25519PrivateKey,
			publicKey:     invalidEd25519publicKey,
			keyID:         keyID,
			payload:       payload,
			wantSignErr:   false,
			wantVerifyErr: true,
		},
		{
			name:          "null keyId (Ed25519)",
			privateKey:    validEd25519PrivateKey,
			publicKey:     validEd25519publicKey,
			keyID:         "",
			payload:       payload,
			wantSignErr:   true,
			wantVerifyErr: false,
		},
		{
			name:          "large payload (Ed25519)",
			privateKey:    validEd25519PrivateKey,
			publicKey:     validEd25519publicKey,
			keyID:         keyID,
			payload:       make([]byte, 100*1024*1024), // 100MB
			wantSignErr:   false,
			wantVerifyErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// sign
			jwsString, err := SignEd25519(tt.payload, tt.privateKey, tt.keyID)
			if err != nil {
				if tt.wantSignErr {
					return
				}
				t.Fatalf("could not sign payload: %v", err)
			}
			if tt.wantSignErr {
				t.Errorf("this test passed when it was expected to fail")
			}

			// verify
			p, err := VerifyEd25519(jwsString, tt.publicKey)
			if err != nil {
				if tt.wantVerifyErr {
					return
				}
				t.Fatalf("could not verify jws: %v", err)
			}
			if tt.wantVerifyErr {
				t.Errorf("this test passed when it was expected to fail")
			}

			if !bytes.Equal(p, tt.payload) {
				t.Errorf("verified payload is not the same as input payload %v: %v", string(p), string(tt.payload))
			}
		})
	}

}

func TestSignAndVerifSignatureRSA(t *testing.T) {

	validRSAPrivateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("could not create RSA key: %v", err)
	}
	validRSApublicKey := validRSAPrivateKey.Public().(*rsa.PublicKey)

	invalidRSAPrivateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("could not create RSA key: %v", err)
	}
	invalidRSApublicKey := invalidRSAPrivateKey.Public().(*rsa.PublicKey)

	if err != nil {
		t.Fatalf("could not create RSA key: %v", err)
	}

	payload := []byte(`{ "message": "Hello, World!" }`)

	keyID := "12345"

	tests := []struct {
		name          string
		privateKey    *rsa.PrivateKey
		publicKey     *rsa.PublicKey
		keyID         string
		payload       []byte
		wantSignErr   bool
		wantVerifyErr bool
	}{
		{
			name:          "valid signature (RSA)",
			privateKey:    validRSAPrivateKey,
			publicKey:     validRSApublicKey,
			keyID:         keyID,
			payload:       payload,
			wantSignErr:   false,
			wantVerifyErr: false,
		},
		{
			name:          "invalid publicKey (RSA)",
			privateKey:    validRSAPrivateKey,
			publicKey:     invalidRSApublicKey,
			keyID:         keyID,
			payload:       payload,
			wantSignErr:   false,
			wantVerifyErr: true,
		},
		{
			name:          "null keyId (RSA)",
			privateKey:    validRSAPrivateKey,
			publicKey:     validRSApublicKey,
			keyID:         "",
			payload:       payload,
			wantSignErr:   true,
			wantVerifyErr: false,
		},
		{
			name:          "large payload (RSA)",
			privateKey:    validRSAPrivateKey,
			publicKey:     validRSApublicKey,
			keyID:         keyID,
			payload:       make([]byte, 100*1024*1024), // 100MB
			wantSignErr:   false,
			wantVerifyErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// sign
			jwsString, err := SignRSA(tt.payload, tt.privateKey, tt.keyID)
			if err != nil {
				if tt.wantSignErr {
					return
				}
				t.Fatalf("could not sign payload: %v", err)
			}
			if tt.wantSignErr {
				t.Errorf("this test passed when it was expected to fail")
			}

			// verify
			p, err := VerifyRSA(jwsString, tt.publicKey)
			if err != nil {
				if tt.wantVerifyErr {
					return
				}
				t.Fatalf("could not verify jws: %v", err)
			}
			if tt.wantVerifyErr {
				t.Errorf("this test passed when it was expected to fail")
			}

			if !bytes.Equal(p, tt.payload) {
				t.Errorf("verified payload is not the same as input payload %v: %v", string(p), string(tt.payload))
			}
		})
	}

}

// loadEd25519PrivateKey loads an Ed25519 private key from PEM file
func loadEd25519PrivateKey(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()

	pemData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatalf("failed to decode PEM block from %s", path)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse private key from %s: %v", path, err)
	}

	ed25519Key, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("key is not Ed25519 private key")
	}

	return ed25519Key
}

// loadRSAPrivateKey loads an RSA private key from PEM file
func loadRSAPrivateKey(t *testing.T, path string) *rsa.PrivateKey {
	t.Helper()

	pemData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatalf("failed to decode PEM block from %s", path)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse private key from %s: %v", path, err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("key is not RSA private key")
	}

	return rsaKey
}

// TestSignRSAWithX5C tests RSA signing with x5c certificate chain
func TestSignRSAWithX5C(t *testing.T) {
	// Use existing RSA test data
	privateKey := loadRSAPrivateKey(t, "testdata/keys/rsa-eblplatform.example.com.private.pem")
	certChain := loadCertChainFromPEM(t, "testdata/certs/rsa-eblplatform.example.com-fullchain.crt")

	payload := []byte(`{"documentChecksum":"abc123","issueToChecksum":"def456", "eBLVisualisationByCarrierChecksum":"789ghi"}`)
	keyID := "test-rsa-key"

	// Sign with x5c
	jwsString, err := SignRSAWithX5C(payload, privateKey, keyID, certChain)
	if err != nil {
		t.Fatalf("SignRSAWithX5C() failed: %v", err)
	}

	// Verify JWS format (header.payload.signature)
	parts := strings.Split(jwsString, ".")
	if len(parts) != 3 {
		t.Fatalf("JWS format invalid: got %d parts, want 3", len(parts))
	}

	// Verify the signature is valid
	publicKey := &privateKey.PublicKey
	verifiedPayload, err := VerifyRSA(jwsString, publicKey)
	if err != nil {
		t.Fatalf("VerifyRSA() failed: %v", err)
	}

	if !bytes.Equal(verifiedPayload, payload) {
		t.Errorf("payload mismatch: got %s, want %s", verifiedPayload, payload)
	}

	// Verify x5c is present in the JWS header
	extractedCerts, err := ParseX5CFromJWS(jwsString)
	if err != nil {
		t.Fatalf("ParseX5CFromJWS() failed: %v", err)
	}

	if len(extractedCerts) != len(certChain) {
		t.Errorf("x5c certificate count = %d, want %d", len(extractedCerts), len(certChain))
	}

	// Verify the certificates match
	for i := range certChain {
		if !extractedCerts[i].Equal(certChain[i]) {
			t.Errorf("certificate %d mismatch", i)
		}
	}

	t.Logf("Successfully signed and verified RSA JWS with x5c chain (%d certs)", len(certChain))

	// test with missing key id
	_, err = SignRSAWithX5C(payload, privateKey, "", certChain)
	if err == nil {
		t.Fatal("SignRSAWithX5C() should fail with empty keyID")
	}

	if !strings.Contains(err.Error(), "keyID is required") {
		t.Errorf("unexpected error: %v", err)
	}

	// test with missing certificate chain
	_, err = SignRSAWithX5C(payload, privateKey, keyID, []*x509.Certificate{})
	if err == nil {
		t.Fatal("SignRSAWithX5C() should fail with empty certificate chain")
	}

	if !strings.Contains(err.Error(), "certificate chain is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestSignEd25519WithX5C tests Ed25519 signing with x5c certificate chain
func TestSignEd25519WithX5C(t *testing.T) {
	// Use existing test data
	privateKey := loadEd25519PrivateKey(t, "testdata/keys/eblplatform.example.com.private.pem")
	certChain := loadCertChainFromPEM(t, "testdata/certs/eblplatform.example.com-fullchain.crt")

	payload := []byte(`{"documentChecksum":"abc123","issueToChecksum":"def456", "eBLVisualisationByCarrierChecksum":"789ghi"}`)
	keyID := "test-ed25519-key"

	// Sign with x5c
	jwsString, err := SignEd25519WithX5C(payload, privateKey, keyID, certChain)
	if err != nil {
		t.Fatalf("SignEd25519WithX5C() failed: %v", err)
	}

	// Verify JWS format
	parts := strings.Split(jwsString, ".")
	if len(parts) != 3 {
		t.Fatalf("JWS format invalid: got %d parts, want 3", len(parts))
	}

	// Verify the signature is valid
	publicKey := privateKey.Public().(ed25519.PublicKey)
	verifiedPayload, err := VerifyEd25519(jwsString, publicKey)
	if err != nil {
		t.Fatalf("VerifyEd25519() failed: %v", err)
	}

	if !bytes.Equal(verifiedPayload, payload) {
		t.Errorf("payload mismatch: got %s, want %s", verifiedPayload, payload)
	}

	// Verify x5c is present in the JWS header
	extractedCerts, err := ParseX5CFromJWS(jwsString)
	if err != nil {
		t.Fatalf("ParseX5CFromJWS() failed: %v", err)
	}

	if len(extractedCerts) != len(certChain) {
		t.Errorf("x5c certificate count = %d, want %d", len(extractedCerts), len(certChain))
	}

	// Verify the certificates match
	for i := range certChain {
		if !extractedCerts[i].Equal(certChain[i]) {
			t.Errorf("certificate %d mismatch", i)
		}
	}

	t.Logf("Successfully signed and verified Ed25519 JWS with x5c chain (%d certs)", len(certChain))

	// test with missing key id
	_, err = SignEd25519WithX5C(payload, privateKey, "", certChain)
	if err == nil {
		t.Fatal("SignEd25519WithX5C() should fail with empty keyID")
	}

	if !strings.Contains(err.Error(), "keyID is required") {
		t.Errorf("unexpected error: %v", err)
	}

	// test with missing cert chain
	_, err = SignEd25519WithX5C(payload, privateKey, keyID, []*x509.Certificate{})
	if err == nil {
		t.Fatal("SignEd25519WithX5C() should fail with empty certificate chain")
	}

	if !strings.Contains(err.Error(), "certificate chain is required") {
		t.Errorf("unexpected error: %v", err)
	}
}
