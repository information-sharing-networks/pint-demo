package crypto

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseX5CFromJWS(t *testing.T) {

	certs, err := ReadCertChainFromPEMFile("testdata/certs/ed25519-eblplatform.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("failed to load test certificates: %v", err)
	}

	testCases := []struct {
		name          string
		setupJWS      func(t *testing.T) string // Function to create the JWS string
		expectedCerts int
		wantError     bool
		expectedError string
	}{
		// Valid cases
		{
			name: "single certificate (leaf only)",
			setupJWS: func(t *testing.T) string {
				fullChain := certs
				leafOnly := fullChain[0:1] // Just the leaf cert, not the full chain
				return makeJWS(t, leafOnly)
			},
			expectedCerts: 1,
			wantError:     false,
		},
		{
			name: "certificate chain (3 certs)",
			setupJWS: func(t *testing.T) string {
				certs := certs
				return makeJWS(t, certs)
			},
			expectedCerts: 3,
			wantError:     false,
		},
		{
			name: "no x5c header (optional)",
			setupJWS: func(t *testing.T) string {
				return makeJWS(t, nil)
			},
			expectedCerts: 0,
			wantError:     false,
		},
		{
			name: "empty x5c array",
			setupJWS: func(t *testing.T) string {
				return makeJWS(t, []*x509.Certificate{})
			},
			expectedCerts: 0,
			wantError:     false,
		},

		{
			name: "malformed: empty string",
			setupJWS: func(t *testing.T) string {
				return ""
			},
			expectedCerts: 0,
			wantError:     true,
			expectedError: "invalid JWS format",
		},
		{
			name: "malformed: missing parts",
			setupJWS: func(t *testing.T) string {
				return "header.payload"
			},
			expectedCerts: 0,
			wantError:     true,
			expectedError: "invalid JWS format",
		},
		{
			name: "malformed: nick invalid base64 header",
			setupJWS: func(t *testing.T) string {
				return "!invalidbase64!.payload.signature"
			},
			expectedCerts: 0,
			wantError:     true,
			expectedError: "failed to decode JWS header",
		},

		// Invalid x5c content (x5c-specific errors)
		{
			name: "invalid x5c: bad base64",
			setupJWS: func(t *testing.T) string {
				return makeFakeJWSWithInvalidX5C(t, []string{"!invalidbase64!"})
			},
			expectedCerts: 0,
			wantError:     true,
			expectedError: "failed to decode certificate",
		},
		{
			name: "invalid x5c: bad DER",
			setupJWS: func(t *testing.T) string {
				invalidDER := base64.StdEncoding.EncodeToString([]byte("not a certificate"))
				return makeFakeJWSWithInvalidX5C(t, []string{invalidDER})
			},
			expectedCerts: 0,
			wantError:     true,
			expectedError: "failed to parse certificate",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// create the JWS string
			jwsString := tc.setupJWS(t)

			parsedCerts, err := ParseX5CFromJWS(jwsString)

			if tc.wantError {
				if err == nil {
					t.Fatalf("expected error containing got nil")
				}
				if tc.expectedError != "" && !strings.Contains(err.Error(), tc.expectedError) {
					t.Errorf("expected error containing %q, got %q", tc.expectedError, err.Error())
				}
				return
			}

			// Verify: no error expected
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify: certificate count
			if len(parsedCerts) != tc.expectedCerts {
				t.Errorf("expected %d certificates, got %d", tc.expectedCerts, len(parsedCerts))
			}
		})
	}
}

// TestValidateCertificateChain tests certificate chain validation
func TestValidateCertificateChain(t *testing.T) {

	certs, err := ReadCertChainFromPEMFile("testdata/certs/ed25519-eblplatform.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("failed to load test certificates: %v", err)
	}

	invalidCerts, err := ReadCertChainFromPEMFile("testdata/certs/ed25519-eblplatform-invalid.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("failed to load test certificates: %v", err)
	}
	testCases := []struct {
		name          string
		setupChain    func(t *testing.T) ([]*x509.Certificate, *x509.CertPool)
		wantError     bool
		expectedError string
	}{
		{
			name: "valid chain with correct domain",
			setupChain: func(t *testing.T) ([]*x509.Certificate, *x509.CertPool) {
				fullChain := certs
				roots := x509.NewCertPool()
				roots.AddCert(fullChain[len(fullChain)-1]) // Add root CA to trusted roots
				return fullChain, roots
			},
			// Domain should be apex domain (from registry), not full hostname
			wantError: false,
		},
		{
			name: "nil chain",
			setupChain: func(t *testing.T) ([]*x509.Certificate, *x509.CertPool) {
				return nil, nil
			},
			wantError:     true,
			expectedError: "empty certificate chain",
		},
		{
			name: "empty chain",
			setupChain: func(t *testing.T) ([]*x509.Certificate, *x509.CertPool) {
				return []*x509.Certificate{}, nil
			},
			wantError:     true,
			expectedError: "empty certificate chain",
		},
		{
			name: "invalid chain (signature mismatch)",
			setupChain: func(t *testing.T) ([]*x509.Certificate, *x509.CertPool) {
				fullChain := invalidCerts
				roots := x509.NewCertPool()
				roots.AddCert(fullChain[len(fullChain)-1])
				return fullChain, roots
			},
			wantError:     true,
			expectedError: "certificate chain validation failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup: create certificate chain and root pool
			certs, roots := tc.setupChain(t)

			// Execute: validate the certificate chain
			err := ValidateCertificateChain(certs, roots)

			// Verify: check error expectation
			if tc.wantError {
				if err == nil {
					t.Fatalf("expected error got nil")
				}
				if tc.expectedError != "" && !strings.Contains(err.Error(), tc.expectedError) {
					t.Errorf("expected error containing %s, got %s", tc.expectedError, err.Error())
				}
				return
			}

			// Verify: no error expected
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestValidateCertificateChain_ExpiredCert tests that expired certificates are rejected
// because of the hacky way we create expired certificates we need to skip if the cert has not expired yet (they expire in 1 day)
func TestValidateCertificateChain_ExpiredCert(t *testing.T) {
	certPEM, err := os.ReadFile("testdata/certs/ed25519-eblplatform-expired.example.com.crt")
	if err != nil {
		t.Fatalf("failed to read expired cert: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Check if cert is actually expired
	now := time.Now()
	if now.Before(cert.NotAfter) {
		t.Skipf("Certificate not yet expired (expires %s, now is %s)", cert.NotAfter, now)
	}

	// Test: expired cert should be rejected
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	err = ValidateCertificateChain([]*x509.Certificate{cert}, roots)

	// Verify we got an expiry error
	var certErr x509.CertificateInvalidError
	if !errors.As(err, &certErr) || certErr.Reason != x509.Expired {
		t.Errorf("expected x509.Expired error, got: %v", err)
	}
}

// makeJWS creates a JWS token (uses a fake signature) - returns JWS string "header.payload.signature"
func makeJWS(t *testing.T, x5cCerts []*x509.Certificate) string {
	t.Helper()

	header := map[string]any{
		"alg": "RS256",
		"kid": "test-key-id",
	}

	// Add x5c if certificates provided
	if x5cCerts != nil {
		x5cArray := make([]string, len(x5cCerts))
		for i, cert := range x5cCerts {
			// x5c format: base64-encoded DER
			x5cArray[i] = base64.StdEncoding.EncodeToString(cert.Raw)
		}
		header["x5c"] = x5cArray
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("failed to marshal header: %v", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	signatureB64 := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))

	return headerB64 + "." + payloadB64 + "." + signatureB64
}

// makeFakeJWSWithInvalidX5C creates a fake JWS with invalid x5c values
func makeFakeJWSWithInvalidX5C(t *testing.T, invalidX5CValues []string) string {
	t.Helper()

	header := map[string]any{
		"alg": "RS256",
		"kid": "test-key-id",
		"x5c": invalidX5CValues,
	}

	// Encode header as JSON
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("failed to marshal header: %v", err)
	}

	// Build JWS: header.payload.signature (all base64url-encoded)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	signatureB64 := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))

	return headerB64 + "." + payloadB64 + "." + signatureB64
}
