package testutil

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jws"
)

// MockKeyProvider implements ebl.KeyProviderWithLookup  - for testing envelope verification
type MockKeyProvider struct {
	keys      map[string]any    // map of KID -> public key
	platforms map[string]string // map of KID -> platform code
}

// NewMockKeyProvider creates a new MockKeyProvider with empty key and platform maps.
func NewMockKeyProvider() *MockKeyProvider {
	return &MockKeyProvider{
		keys:      make(map[string]any),
		platforms: make(map[string]string),
	}
}

// AddKeyWithPlatform adds a public key and associates it with a platform code.
// kid = jwk thumbprint
func (m *MockKeyProvider) AddKeyWithPlatform(kid string, key any, platformCode string) {
	m.keys[kid] = key
	m.platforms[kid] = platformCode
}

// FetchKeys implements jws.KeyProvider (retrieves keys based on KID in JWS header)
func (m *MockKeyProvider) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
	kid, ok := sig.ProtectedHeaders().KeyID()
	if !ok || kid == "" {
		return fmt.Errorf("kid is required in JWS header")
	}
	alg, ok := sig.ProtectedHeaders().Algorithm()
	if !ok {
		return fmt.Errorf("alg is required in JWS header")
	}

	key, exists := m.keys[kid]
	if !exists {
		return fmt.Errorf("key not found for kid: %s", kid)
	}

	sink.Key(alg, key)
	return nil
}

// LookupPlatformByKeyID implements the KeyProviderWithLookup
func (m *MockKeyProvider) LookupPlatformByKeyID(ctx context.Context, keyID string) (string, error) {
	platform, exists := m.platforms[keyID]
	if !exists {
		return "", fmt.Errorf("platform not found for key: %s", keyID)
	}
	return platform, nil
}
