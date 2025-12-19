package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
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
