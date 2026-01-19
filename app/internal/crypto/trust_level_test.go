package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

func TestDetermineTrustLevel(t *testing.T) {
	tests := []struct {
		name          string
		jws           string
		expectedLevel TrustLevel
		expectError   bool
	}{
		{
			name: "No x5c header - TrustLevelNoX5C",
			// Simple JWS without x5c header
			jws: createTestJWS(t, map[string]any{
				"alg": "EdDSA",
				"kid": "test-key",
			}),
			expectedLevel: TrustLevelNoX5C,
			expectError:   false,
		},
		{
			name: "x5c with Organization field - TrustLevelEVOV",
			// JWS with x5c containing a cert with Organization
			jws:           createTestJWSWithMockX5C(t, true),
			expectedLevel: TrustLevelEVOV,
			expectError:   false,
		},
		{
			name: "x5c without Organization field - TrustLevelDV",
			// JWS with x5c containing a cert without Organization
			jws:           createTestJWSWithMockX5C(t, false),
			expectedLevel: TrustLevelDV,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level, err := DetermineTrustLevel(tt.jws)

			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if level != tt.expectedLevel {
				t.Errorf("expected trust level %s, got %s",
					tt.expectedLevel.String(), level.String())
			}
		})
	}
}

// Helper to create a simple JWS without x5c
func createTestJWS(t *testing.T, header map[string]any) string {
	t.Helper()

	headerJSON, _ := json.Marshal(header)
	payload := []byte(`{"test":"data"}`)
	signature := []byte("fake-signature")

	return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(signature)
}

// Helper to create a JWS with a mock x5c certificate
func createTestJWSWithMockX5C(t *testing.T, withOrganization bool) string {
	t.Helper()

	// Create a simple self-signed certificate
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	if withOrganization {
		template.Subject.Organization = []string{"Example Corp"}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Create JWS with x5c
	payload := []byte(`{"test":"data"}`)
	jws, err := SignJSONWithEd25519AndX5C(payload, privateKey, "test-key", []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("failed to create JWS with x5c: %v", err)
	}

	return jws
}
