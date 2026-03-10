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

// TestParseHeader covers that ParseJWSHeader rejects tokens with unexpected header fields such as typ.
func TestParseHeader(t *testing.T) {
	// { "alg": "HS256", "typ": "JWT" } (unexpected header: typ)
	invalidJwsToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"

	header, err := ParseJWSHeader(invalidJwsToken)
	if err == nil {
		t.Errorf("ParseHeader failed to reject an invalid header - got: %v", header)
	}
}

// TestSignAndVerifySignature covers Ed25519 and RSA JWS sign and verify,
// including mismatched key and missing keyID cases for both algorithms.
func TestSignAndVerifySignature(t *testing.T) {
	ed25519Key, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("could not create Ed25519 key: %v", err)
	}
	wrongEd25519Key, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("could not create Ed25519 key: %v", err)
	}

	rsaKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("could not create RSA key: %v", err)
	}
	wrongRSAKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("could not create RSA key: %v", err)
	}

	payload, err := CanonicalizeJSON([]byte(`{ "message": "Hello, World!" }`))
	if err != nil {
		t.Fatalf("could not canonicalize test payload: %v", err)
	}

	keyID := "12345"

	tests := []struct {
		name          string
		sign          func(payload []byte, keyID string) (string, error)
		verify        func(token string) ([]byte, error)
		keyID         string
		payload       []byte
		wantSignErr   bool
		wantVerifyErr bool
	}{
		{
			name: "valid (Ed25519)",
			sign: func(p []byte, kid string) (string, error) { return SignJSONWithEd25519(p, ed25519Key, kid) },
			verify: func(tok string) ([]byte, error) {
				return VerifyJWSEd25519(tok, ed25519Key.Public().(ed25519.PublicKey))
			},
			keyID:   keyID,
			payload: payload,
		},
		{
			name: "wrong public key (Ed25519)",
			sign: func(p []byte, kid string) (string, error) { return SignJSONWithEd25519(p, ed25519Key, kid) },
			verify: func(tok string) ([]byte, error) {
				return VerifyJWSEd25519(tok, wrongEd25519Key.Public().(ed25519.PublicKey))
			},
			keyID:         keyID,
			payload:       payload,
			wantVerifyErr: true,
		},
		{
			name: "empty keyID (Ed25519)",
			sign: func(p []byte, kid string) (string, error) { return SignJSONWithEd25519(p, ed25519Key, kid) },
			verify: func(tok string) ([]byte, error) {
				return VerifyJWSEd25519(tok, ed25519Key.Public().(ed25519.PublicKey))
			},
			keyID:       "",
			payload:     payload,
			wantSignErr: true,
		},
		{
			name: "large payload (Ed25519)",
			sign: func(p []byte, kid string) (string, error) { return SignJSONWithEd25519(p, ed25519Key, kid) },
			verify: func(tok string) ([]byte, error) {
				return VerifyJWSEd25519(tok, ed25519Key.Public().(ed25519.PublicKey))
			},
			keyID:   keyID,
			payload: []byte(`{"data":"` + strings.Repeat("x", 1024*1024) + `"}`),
		},
		{
			name:    "valid (RSA)",
			sign:    func(p []byte, kid string) (string, error) { return SignJSONWithRSA(p, rsaKey, kid) },
			verify:  func(tok string) ([]byte, error) { return VerifyJWSRSA(tok, &rsaKey.PublicKey) },
			keyID:   keyID,
			payload: payload,
		},
		{
			name:          "wrong public key (RSA)",
			sign:          func(p []byte, kid string) (string, error) { return SignJSONWithRSA(p, rsaKey, kid) },
			verify:        func(tok string) ([]byte, error) { return VerifyJWSRSA(tok, &wrongRSAKey.PublicKey) },
			keyID:         keyID,
			payload:       payload,
			wantVerifyErr: true,
		},
		{
			name:        "empty keyID (RSA)",
			sign:        func(p []byte, kid string) (string, error) { return SignJSONWithRSA(p, rsaKey, kid) },
			verify:      func(tok string) ([]byte, error) { return VerifyJWSRSA(tok, &rsaKey.PublicKey) },
			keyID:       "",
			payload:     payload,
			wantSignErr: true,
		},
		{
			name:    "large payload (RSA)",
			sign:    func(p []byte, kid string) (string, error) { return SignJSONWithRSA(p, rsaKey, kid) },
			verify:  func(tok string) ([]byte, error) { return VerifyJWSRSA(tok, &rsaKey.PublicKey) },
			keyID:   keyID,
			payload: []byte(`{"data":"` + strings.Repeat("x", 1024*1024) + `"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := tt.sign(tt.payload, tt.keyID)
			if err != nil {
				if tt.wantSignErr {
					return
				}
				t.Fatalf("could not sign payload: %v", err)
			}
			if tt.wantSignErr {
				t.Errorf("expected sign error but got none")
			}

			verified, err := tt.verify(token)
			if err != nil {
				if tt.wantVerifyErr {
					return
				}
				t.Fatalf("could not verify JWS: %v", err)
			}
			if tt.wantVerifyErr {
				t.Errorf("expected verify error but got none")
			}

			if !bytes.Equal(verified, tt.payload) {
				t.Errorf("verified payload does not match input.\nGot: %s\nWant: %s", verified, tt.payload)
			}
		})
	}
}

// TestSignWithX5C covers Ed25519 and RSA JWS signing with x5c certificate chains:
// verifies signature, payload integrity, and cert extraction; rejects empty keyID or empty cert chain.
func TestSignWithX5C(t *testing.T) {
	ed25519Key, err := ReadEd25519PrivateKeyFromJWKFile("../../test/testdata/keys/private/ed25519-eblplatform.example.com.private.jwk")
	if err != nil {
		t.Fatalf("failed to load Ed25519 private key: %v", err)
	}
	ed25519CertChain, err := ReadCertChainFromPEMFile("../../test/testdata/certs/ed25519-eblplatform.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("failed to load Ed25519 cert chain: %v", err)
	}

	rsaKey, err := ReadRSAPrivateKeyFromPEMFile("../../test/testdata/keys/pem/rsa-eblplatform.example.com.private.pem")
	if err != nil {
		t.Fatalf("failed to load RSA private key: %v", err)
	}
	rsaCertChain, err := ReadCertChainFromPEMFile("../../test/testdata/certs/rsa-eblplatform.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("failed to load RSA cert chain: %v", err)
	}

	payload, err := CanonicalizeJSON([]byte(`{"documentChecksum":"abc123","issueToChecksum":"def456","eBLVisualisationByCarrierChecksum":"ghi789"}`))
	if err != nil {
		t.Fatalf("failed to canonicalize test payload: %v", err)
	}

	tests := []struct {
		name      string
		keyID     string
		certChain []*x509.Certificate
		sign      func(payload []byte, keyID string, certChain []*x509.Certificate) (string, error)
		verify    func(token string) ([]byte, error)
	}{
		{
			name:      "Ed25519",
			keyID:     "test-ed25519-key",
			certChain: ed25519CertChain,
			sign: func(p []byte, kid string, chain []*x509.Certificate) (string, error) {
				return SignJSONWithEd25519AndX5C(p, ed25519Key, kid, chain)
			},
			verify: func(tok string) ([]byte, error) {
				return VerifyJWSEd25519(tok, ed25519Key.Public().(ed25519.PublicKey))
			},
		},
		{
			name:      "RSA",
			keyID:     "test-rsa-key",
			certChain: rsaCertChain,
			sign: func(p []byte, kid string, chain []*x509.Certificate) (string, error) {
				return SignJSONWithRSAAndX5C(p, rsaKey, kid, chain)
			},
			verify: func(tok string) ([]byte, error) { return VerifyJWSRSA(tok, &rsaKey.PublicKey) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := tt.sign(payload, tt.keyID, tt.certChain)
			if err != nil {
				t.Fatalf("sign failed: %v", err)
			}

			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				t.Fatalf("JWS format invalid: got %d parts, want 3", len(parts))
			}

			verifiedPayload, err := tt.verify(token)
			if err != nil {
				t.Fatalf("verify failed: %v", err)
			}
			if !bytes.Equal(verifiedPayload, payload) {
				t.Errorf("payload mismatch: got %s, want %s", verifiedPayload, payload)
			}

			extractedCerts, err := ParseX5CFromJWS(token)
			if err != nil {
				t.Fatalf("ParseX5CFromJWS() failed: %v", err)
			}
			if len(extractedCerts) != len(tt.certChain) {
				t.Errorf("x5c certificate count = %d, want %d", len(extractedCerts), len(tt.certChain))
			}
			for i := range tt.certChain {
				if !extractedCerts[i].Equal(tt.certChain[i]) {
					t.Errorf("certificate %d mismatch", i)
				}
			}

			_, err = tt.sign(payload, "", tt.certChain)
			if err == nil {
				t.Fatal("expected error for empty keyID, got none")
			}
			if !strings.Contains(err.Error(), "keyID is required") {
				t.Errorf("unexpected error for empty keyID: %v", err)
			}

			_, err = tt.sign(payload, tt.keyID, []*x509.Certificate{})
			if err == nil {
				t.Fatal("expected error for empty cert chain, got none")
			}
			if !strings.Contains(err.Error(), "certificate chain is required") {
				t.Errorf("unexpected error for empty cert chain: %v", err)
			}
		})
	}
}

// TestGenerateKeyIDFromKey covers key ID generation for Ed25519 and RSA public keys;
// verifies the 16-character output length for both algorithms.
func TestGenerateKeyIDFromKey(t *testing.T) {
	ed25519Key, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key pair: %v", err)
	}
	rsaKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key pair: %v", err)
	}

	tests := []struct {
		name     string
		generate func() (string, error)
	}{
		{name: "Ed25519", generate: func() (string, error) { return GenerateDefaultKeyID(ed25519Key.Public().(ed25519.PublicKey)) }},
		{name: "RSA", generate: func() (string, error) { return GenerateDefaultKeyID(&rsaKey.PublicKey) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID, err := tt.generate()
			if err != nil {
				t.Fatalf("failed to generate key ID: %v", err)
			}
			if len(keyID) != 16 {
				t.Errorf("key ID length = %d, want 16", len(keyID))
			}
		})
	}
}

// TestSignJSON tests the convenience SignJSON function with both Ed25519 and RSA keys
func TestSignJSON(t *testing.T) {
	// Load test keys and certificates
	ed25519PrivateKey, err := ReadEd25519PrivateKeyFromJWKFile("../../test/testdata/keys/private/ed25519-eblplatform.example.com.private.jwk")
	if err != nil {
		t.Fatalf("failed to load Ed25519 private key: %v", err)
	}
	ed25519PublicKey := ed25519PrivateKey.Public().(ed25519.PublicKey)

	ed25519CertChain, err := ReadCertChainFromPEMFile("../../test/testdata/certs/ed25519-eblplatform.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("failed to load Ed25519 cert chain: %v", err)
	}

	rsaPrivateKey, err := ReadRSAPrivateKeyFromJWKFile("../../test/testdata/keys/private/rsa-eblplatform.example.com.private.jwk")
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

// TestVerifyJWS covers multi-key JWS verification including x5c chain validation, x5c mismatch detection, and unknown key ID rejection.
func TestVerifyJWS(t *testing.T) {
	// Load platform key + certs (key A)
	platformPrivateKey, err := ReadEd25519PrivateKeyFromJWKFile("../../test/testdata/keys/private/ed25519-eblplatform.example.com.private.jwk")
	if err != nil {
		t.Fatalf("failed to load platform private key: %v", err)
	}

	platformPublicKey := platformPrivateKey.Public().(ed25519.PublicKey)
	platformKeyID, err := GenerateDefaultKeyID(platformPublicKey)
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
				otherKID, _ := GenerateDefaultKeyID(otherPub)
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
