package crypto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jws"
)

func TestParseHeader(t *testing.T) {
	// { "alg": "HS256", "typ": "JWT" } (unexpected header: typ)
	invalidJwsToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"

	header, err := ParseJWSHeader(invalidJwsToken)
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

	payload, err := CanonicalizeJSON([]byte(`{ "message": "Hello, World!" }`))
	if err != nil {
		t.Fatalf("could not canonicalize test payload: %v", err)
	}

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
			payload:       []byte(`{"data":"` + strings.Repeat("x", 1024*1024) + `"}`),
			wantSignErr:   false,
			wantVerifyErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// sign
			JwsToken, err := SignJSONWithEd25519(tt.payload, tt.privateKey, tt.keyID)
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
			p, err := VerifyJWSEd25519(JwsToken, tt.publicKey)
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
				t.Errorf("verified payload is not the same as canonical input payload.\nGot: %s\nWant: %s", string(p), string(tt.payload))
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

	payload, err := CanonicalizeJSON([]byte(`{ "message": "Hello, World!" }`))
	if err != nil {
		t.Fatalf("could not canonicalize test payload: %v", err)
	}

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
			payload:       []byte(`{"data":"` + strings.Repeat("x", 1024*1024) + `"}`),
			wantSignErr:   false,
			wantVerifyErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// sign
			JwsToken, err := SignJSONWithRSA(tt.payload, tt.privateKey, tt.keyID)
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
			p, err := VerifyJWSRSA(JwsToken, tt.publicKey)
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
				t.Errorf("verified payload is not the same as canonical input payload.\nGot: %s\nWant: %s", string(p), string(tt.payload))
			}
		})
	}

}

// TestSignRSAWithX5C tests RSA signing with x5c certificate chain
func TestSignRSAWithX5C(t *testing.T) {
	// Use existing RSA test data
	privateKey, err := ReadRSAPrivateKeyFromPEMFile("../../test/testdata/keys/rsa-eblplatform.example.com.private.pem")
	if err != nil {
		t.Fatalf("failed to load test private key: %v", err)
	}
	certChain, err := ReadCertChainFromPEMFile("../../test/testdata/certs/rsa-eblplatform.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("failed to load test certificates: %v", err)
	}

	// cannoicalized test payload
	payload, err := CanonicalizeJSON([]byte(`{"documentChecksum":"abc123","issueToChecksum":"def456", "eBLVisualisationByCarrierChecksum":"ghi789"}`))
	if err != nil {
		t.Fatalf("failed to canonicalize test payload: %v", err)
	}
	keyID := "test-rsa-key"

	// Sign with x5c
	JwsToken, err := SignJSONWithRSAAndX5C(payload, privateKey, keyID, certChain)
	if err != nil {
		t.Fatalf("SignRSAWithX5C() failed: %v", err)
	}

	// Verify JWS format (header.payload.signature)
	parts := strings.Split(JwsToken, ".")
	if len(parts) != 3 {
		t.Fatalf("JWS format invalid: got %d parts, want 3", len(parts))
	}

	// Verify the signature is valid
	publicKey := &privateKey.PublicKey
	verifiedPayload, err := VerifyJWSRSA(JwsToken, publicKey)
	if err != nil {
		t.Fatalf("VerifyRSA() failed: %v", err)
	}

	if !bytes.Equal(verifiedPayload, payload) {
		t.Errorf("payload mismatch: got %s, want %s", verifiedPayload, payload)
	}

	// Verify x5c is present in the JWS header
	extractedCerts, err := ParseX5CFromJWS(JwsToken)
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
	_, err = SignJSONWithRSAAndX5C(payload, privateKey, "", certChain)
	if err == nil {
		t.Fatal("SignRSAWithX5C() should fail with empty keyID")
	}

	if !strings.Contains(err.Error(), "keyID is required") {
		t.Errorf("unexpected error: %v", err)
	}

	// test with missing certificate chain
	_, err = SignJSONWithRSAAndX5C(payload, privateKey, keyID, []*x509.Certificate{})
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
	privateKey, err := ReadEd25519PrivateKeyFromJWKFile("../../test/testdata/keys/ed25519-eblplatform.example.com.private.jwk")
	if err != nil {
		t.Fatalf("failed to load test private key: %v", err)
	}
	certChain, err := ReadCertChainFromPEMFile("../../test/testdata/certs/ed25519-eblplatform.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("failed to load test certificates: %v", err)
	}

	payload, err := CanonicalizeJSON([]byte(`{"documentChecksum":"abc123","issueToChecksum":"def456", "eBLVisualisationByCarrierChecksum":"789ghi"}`))
	if err != nil {
		t.Fatalf("failed to canonicalize test payload: %v", err)
	}
	keyID := "test-ed25519-key"

	// Sign with x5c
	JwsToken, err := SignJSONWithEd25519AndX5C(payload, privateKey, keyID, certChain)
	if err != nil {
		t.Fatalf("SignEd25519WithX5C() failed: %v", err)
	}

	// Verify JWS format
	parts := strings.Split(JwsToken, ".")
	if len(parts) != 3 {
		t.Fatalf("JWS format invalid: got %d parts, want 3", len(parts))
	}

	// Verify the signature is valid
	publicKey := privateKey.Public().(ed25519.PublicKey)
	verifiedPayload, err := VerifyJWSEd25519(JwsToken, publicKey)
	if err != nil {
		t.Fatalf("VerifyEd25519() failed: %v", err)
	}

	if !bytes.Equal(verifiedPayload, payload) {
		t.Errorf("payload mismatch: got %s, want %s", verifiedPayload, payload)
	}

	// Verify x5c is present in the JWS header
	extractedCerts, err := ParseX5CFromJWS(JwsToken)
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
	_, err = SignJSONWithEd25519AndX5C(payload, privateKey, "", certChain)
	if err == nil {
		t.Fatal("SignEd25519WithX5C() should fail with empty keyID")
	}

	if !strings.Contains(err.Error(), "keyID is required") {
		t.Errorf("unexpected error: %v", err)
	}

	// test with missing cert chain
	_, err = SignJSONWithEd25519AndX5C(payload, privateKey, keyID, []*x509.Certificate{})
	if err == nil {
		t.Fatal("SignEd25519WithX5C() should fail with empty certificate chain")
	}

	if !strings.Contains(err.Error(), "certificate chain is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestGenerateKeyIDFromEd25519Key tests generating a key ID from an Ed25519 public key
func TestGenerateKeyIDFromEd25519Key(t *testing.T) {
	// Generate a key pair
	privateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Generate key ID
	keyID, err := GenerateKeyIDFromEd25519Key(publicKey)
	if err != nil {
		t.Fatalf("failed to generate key ID: %v", err)
	}

	// Verify key ID is 16 characters
	if len(keyID) != 16 {
		t.Errorf("key ID length = %d, want 16", len(keyID))
	}
}

// TestGenerateKeyIDFromRSAKey tests generating a key ID from an RSA public key
func TestGenerateKeyIDFromRSAKey(t *testing.T) {
	// Generate a key pair
	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	publicKey := &privateKey.PublicKey

	// Generate key ID
	keyID, err := GenerateKeyIDFromRSAKey(publicKey)
	if err != nil {
		t.Fatalf("failed to generate key ID: %v", err)
	}

	// Verify key ID is 16 characters
	if len(keyID) != 16 {
		t.Errorf("key ID length = %d, want 16", len(keyID))
	}
}

// TestSignJSON tests the convenience SignJSON function with both Ed25519 and RSA keys
func TestSignJSON(t *testing.T) {
	// Load test keys and certificates
	ed25519PrivateKey, err := ReadEd25519PrivateKeyFromJWKFile("../../test/testdata/keys/ed25519-eblplatform.example.com.private.jwk")
	if err != nil {
		t.Fatalf("failed to load Ed25519 private key: %v", err)
	}
	ed25519PublicKey := ed25519PrivateKey.Public().(ed25519.PublicKey)

	ed25519CertChain, err := ReadCertChainFromPEMFile("../../test/testdata/certs/ed25519-eblplatform.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("failed to load Ed25519 cert chain: %v", err)
	}

	rsaPrivateKey, err := ReadRSAPrivateKeyFromJWKFile("../../test/testdata/keys/rsa-eblplatform.example.com.private.jwk")
	if err != nil {
		t.Fatalf("failed to load RSA private key: %v", err)
	}
	rsaPublicKey := &rsaPrivateKey.PublicKey

	rsaCertChain, err := ReadCertChainFromPEMFile("../../test/testdata/certs/rsa-eblplatform.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("failed to load RSA cert chain: %v", err)
	}

	payload := []byte(`{"test":"data"}`)

	tests := []struct {
		name       string
		privateKey any
		certChain  []*x509.Certificate
		publicKey  any
		wantErr    bool
	}{
		{
			name:       "Ed25519 with x5c",
			privateKey: ed25519PrivateKey,
			certChain:  ed25519CertChain,
			publicKey:  ed25519PublicKey,
			wantErr:    false,
		},
		{
			name:       "Ed25519 without x5c",
			privateKey: ed25519PrivateKey,
			certChain:  nil,
			publicKey:  ed25519PublicKey,
			wantErr:    false,
		},
		{
			name:       "RSA with x5c",
			privateKey: rsaPrivateKey,
			certChain:  rsaCertChain,
			publicKey:  rsaPublicKey,
			wantErr:    false,
		},
		{
			name:       "RSA without x5c",
			privateKey: rsaPrivateKey,
			certChain:  nil,
			publicKey:  rsaPublicKey,
			wantErr:    false,
		},
		{
			name:       "Unsupported key type",
			privateKey: "not-a-key",
			certChain:  nil,
			publicKey:  nil,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Sign the payload
			jws, err := SignJSON(payload, tt.privateKey, tt.certChain)

			if tt.wantErr {
				if err == nil {
					t.Errorf("SignJSON() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("SignJSON() error = %v", err)
			}

			// Verify the JWS format
			parts := strings.Split(jws, ".")
			if len(parts) != 3 {
				t.Fatalf("JWS format invalid: got %d parts, want 3", len(parts))
			}

			// Verify the signature
			var verifiedPayload []byte
			switch key := tt.publicKey.(type) {
			case ed25519.PublicKey:
				verifiedPayload, err = VerifyJWSEd25519(jws, key)
			case *rsa.PublicKey:
				verifiedPayload, err = VerifyJWSRSA(jws, key)
			}

			if err != nil {
				t.Fatalf("Failed to verify signature: %v", err)
			}

			// Verify payload matches
			if !bytes.Equal(verifiedPayload, payload) {
				t.Errorf("Payload mismatch: got %s, want %s", verifiedPayload, payload)
			}

			// Verify x5c presence
			extractedCerts, err := ParseX5CFromJWS(jws)
			if err != nil {
				t.Fatalf("ParseX5CFromJWS() error = %v", err)
			}

			if tt.certChain != nil {
				if extractedCerts == nil {
					t.Errorf("Expected x5c cert chain but got nil")
				} else if len(extractedCerts) != len(tt.certChain) {
					t.Errorf("x5c cert count = %d, want %d", len(extractedCerts), len(tt.certChain))
				}
			} else {
				if extractedCerts != nil {
					t.Errorf("Expected no x5c cert chain but got %d certs", len(extractedCerts))
				}
			}
		})
	}
}

// testKeyProvider is a minimal jws.KeyProvider for unit testing VerifyJWS.
type testKeyProvider struct {
	keys map[string]any // kid -> raw public key
}

func (p *testKeyProvider) FetchKeys(_ context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
	kid, ok := sig.ProtectedHeaders().KeyID()
	if !ok || kid == "" {
		return fmt.Errorf("kid is required")
	}
	alg, ok := sig.ProtectedHeaders().Algorithm()
	if !ok {
		return fmt.Errorf("alg is required")
	}
	key, exists := p.keys[kid]
	if !exists {
		return fmt.Errorf("key not found: %s", kid)
	}
	sink.Key(alg, key)
	return nil
}

func TestVerifyJWS(t *testing.T) {
	// Load platform key + certs (key A)
	platformPrivateKey, err := ReadEd25519PrivateKeyFromJWKFile("../../test/testdata/keys/ed25519-eblplatform.example.com.private.jwk")
	if err != nil {
		t.Fatalf("failed to load platform private key: %v", err)
	}

	platformPublicKey := platformPrivateKey.Public().(ed25519.PublicKey)
	platformKeyID, err := GenerateKeyIDFromEd25519Key(platformPublicKey)
	if err != nil {
		t.Fatalf("failed to generate platform key ID: %v", err)
	}

	platformCertChain, err := ReadCertChainFromPEMFile("../../test/testdata/certs/ed25519-eblplatform.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("failed to load platform cert chain: %v", err)
	}

	// Load carrier certs (key B) — different org, different key
	carrierCertChain, err := ReadCertChainFromPEMFile("../../test/testdata/certs/ed25519-carrier.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("failed to load carrier cert chain: %v", err)
	}

	// Root CA pool
	rootCAs := x509.NewCertPool()
	rootCABytes, err := os.ReadFile("../../test/testdata/certs/root-ca.crt")
	if err != nil {
		t.Fatalf("failed to load root CA: %v", err)
	}
	if !rootCAs.AppendCertsFromPEM(rootCABytes) {
		t.Fatalf("failed to parse root CA")
	}

	// KeyProvider that returns the platform public key
	provider := &testKeyProvider{
		keys: map[string]any{platformKeyID: platformPublicKey},
	}

	tests := []struct {
		name            string
		setupJWS        func() string
		rootCAs         *x509.CertPool
		expectCertX5C   bool
		expectError     bool
		expectedErrCode ErrorCode
	}{
		{
			name: "valid JWS with matching x5c",
			setupJWS: func() string {
				jwsStr, _ := SignJSONWithEd25519AndX5C([]byte(`{"test":"data"}`), platformPrivateKey, platformKeyID, platformCertChain)
				return jwsStr
			},
			rootCAs:       rootCAs,
			expectCertX5C: true,
			expectError:   false,
		},
		{
			name: "valid JWS without x5c",
			setupJWS: func() string {
				jwsStr, _ := SignJSONWithEd25519([]byte(`{"test":"data"}`), platformPrivateKey, platformKeyID)
				return jwsStr
			},
			rootCAs:       nil,
			expectCertX5C: false,
			expectError:   false,
		},
		{
			name: "x5c mismatch - signed with platform key but carrier x5c attached",
			setupJWS: func() string {
				// Sign with platform key but include carrier's certificate chain.
				// The signature is valid (KeyProvider returns platform key), but the
				// x5c certificate chain belongs to a different organization.
				jwsStr, _ := SignJSONWithEd25519AndX5C([]byte(`{"test":"data"}`), platformPrivateKey, platformKeyID, carrierCertChain)
				return jwsStr
			},
			rootCAs:         rootCAs,
			expectError:     true,
			expectedErrCode: ErrCodeCertificate,
		},
		{
			name: "unknown key ID",
			setupJWS: func() string {
				// Generate a throwaway key — not registered in the provider
				otherKey, _ := GenerateEd25519KeyPair()
				otherPub := otherKey.Public().(ed25519.PublicKey)
				otherKID, _ := GenerateKeyIDFromEd25519Key(otherPub)
				jwsStr, _ := SignJSONWithEd25519([]byte(`{"test":"data"}`), otherKey, otherKID)
				return jwsStr
			},
			rootCAs:         nil,
			expectError:     true,
			expectedErrCode: ErrCodeInvalidSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, _, certChain, err := VerifyJWS(tt.setupJWS(), provider, tt.rootCAs)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				if tt.expectedErrCode != "" {
					var cryptoErr Error
					if errors.As(err, &cryptoErr) {
						if cryptoErr.Code() != tt.expectedErrCode {
							t.Errorf("expected error code %q, got %q (error: %v)", tt.expectedErrCode, cryptoErr.Code(), err)
						}
					} else {
						t.Errorf("expected CryptoError with code %q, got non-crypto error: %v", tt.expectedErrCode, err)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if payload == nil {
				t.Errorf("expected payload but got nil")
			}
			if tt.expectCertX5C && certChain == nil {
				t.Errorf("expected cert chain but got nil")
			}
			if !tt.expectCertX5C && certChain != nil {
				t.Errorf("expected nil cert chain, got %d certs", len(certChain))
			}
		})
	}
}
