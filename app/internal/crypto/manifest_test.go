package crypto

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// Test data for issuance manifest tests
var (
	testDocument                         = []byte(`{"transportDocumentReference":"MAEU123456"}`)
	testIssueTo                          = []byte(`{"partyName":"Test Company"}`)
	testEblVisualisationByCarrier        = []byte(`mock pdf binary content here`)
	testEblVisualisationByCarrierContent = base64.StdEncoding.EncodeToString(testEblVisualisationByCarrier)
)

func TestIssuanceManifestBuilderNew(t *testing.T) {
	tests := []struct {
		name          string
		document      []byte
		issueTo       []byte
		visualization string
		wantErr       bool
	}{
		{
			name:     "valid - no visualization",
			document: testDocument,
			issueTo:  testIssueTo,
			wantErr:  false,
		},
		{
			name:          "valid - including visualization",
			document:      testDocument,
			issueTo:       testIssueTo,
			visualization: testEblVisualisationByCarrierContent,
			wantErr:       false,
		},
		{
			name:     "missing document",
			document: nil,
			issueTo:  testIssueTo,
			wantErr:  true,
		},
		{
			name:     "missing issueTo",
			document: testDocument,
			issueTo:  nil,
			wantErr:  true,
		},
		{
			name:     "invalid document json",
			document: []byte(`invalid json`),
			issueTo:  testIssueTo,
			wantErr:  true,
		},
		{
			name:     "invalid issueTo json",
			document: testDocument,
			issueTo:  []byte(`invalid json`),
			wantErr:  true,
		},
		{
			name:          "valid base64 encoded visualization",
			document:      testDocument,
			issueTo:       testIssueTo,
			visualization: base64.StdEncoding.EncodeToString([]byte{0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34}),
			wantErr:       false,
		},
		{
			name:          "invalid - raw binary visualization (not base64)",
			document:      testDocument,
			issueTo:       testIssueTo,
			visualization: string([]byte{0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34}), // Raw binary as string (not base64)
			wantErr:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewIssuanceManifestBuilder()
			if tt.document != nil {
				builder.WithDocument(tt.document)
			}
			if tt.issueTo != nil {
				builder.WithIssueTo(tt.issueTo)
			}
			if tt.visualization != "" {
				builder.WithEBLVisualisation(tt.visualization)
			}
			manifest, err := builder.Build()
			if (err != nil) != tt.wantErr {
				t.Errorf("IssuanceManifestBuilder.Build() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}
			// Ensure manifest is not nil before accessing fields
			if manifest == nil {
				t.Fatal("Build() returned nil manifest without error")
			}

			// Verify checksums
			if manifest.DocumentChecksum == "" {
				t.Error("DocumentChecksum is empty")
			}
			if len(manifest.DocumentChecksum) != 64 {
				t.Errorf("DocumentChecksum length = %d, want 64", len(manifest.DocumentChecksum))
			}
			if manifest.IssueToChecksum == "" {
				t.Error("IssueToChecksum is empty")
			}
			if len(manifest.IssueToChecksum) != 64 {
				t.Errorf("IssueToChecksum length = %d, want 64", len(manifest.IssueToChecksum))
			}
			if tt.visualization != "" && (manifest.EBLVisualisationByCarrierChecksum == nil || *manifest.EBLVisualisationByCarrierChecksum == "") {
				t.Error("EBLVisualisationByCarrierChecksum should be set")
			}
			if tt.visualization != "" && len(*manifest.EBLVisualisationByCarrierChecksum) != 64 {
				t.Errorf("EBLVisualisationByCarrierChecksum length = %d, want 64",
					len(*manifest.EBLVisualisationByCarrierChecksum))
			}
		})
	}
}

// sanity check to confirm we can correctly recreate the manually computed signtures in
// HHL71800000-ed25519.json and HHL71800000-rsa.json
func TestRecreateSampleIssuanceManifestEd25519(t *testing.T) {

	sampleRecordPath := "testdata/transport-documents/HHL71800000-ed25519.json"
	privateKeyPath := "testdata/transport-documents/keys/ed25519-carrier.example.com.private.jwk"
	keyID := "testkid"
	certPath := "testdata/transport-documents/certs/ed25519-carrier.example.com-fullchain.crt"

	data, err := os.ReadFile(sampleRecordPath)
	if err != nil {
		t.Fatalf("could not open %s: %v", sampleRecordPath, err)
	}

	privateKey, err := ReadEd25519PrivateKeyFromJWKFile(privateKeyPath)
	if err != nil {
		t.Fatalf("Could not read private key file %s: %e", privateKeyPath, err)
	}

	certChain, err := ReadCertChainFromPEMFile(certPath)
	if err != nil {
		t.Fatalf("could not load cert chain from %s: %e", certPath, err)
	}

	var sampleIssuanceRequest struct {
		Document                  json.RawMessage `json:"document"`
		IssueTo                   json.RawMessage `json:"issueTo"`
		EBLVisualisationByCarrier struct {
			Name        string `json:"name"`
			Content     string `json:"content"`
			ContentType string `json:"contentType"`
		} `json:"eBLVisualisationByCarrier"`
		IssuanceManifestSignedContent string `json:"issuanceManifestSignedContent"`
	}
	err = json.Unmarshal(data, &sampleIssuanceRequest)
	if err != nil {
		t.Fatalf("could not marshal bl json: %v", err)
	}

	// recreate issuance manifest
	manifest := NewIssuanceManifestBuilder()
	manifest.WithDocument(sampleIssuanceRequest.Document)
	manifest.WithIssueTo(sampleIssuanceRequest.IssueTo)
	// content is already base64 encoded
	manifest.WithEBLVisualisation(sampleIssuanceRequest.EBLVisualisationByCarrier.Content)

	issuanceManifest, err := manifest.Build()
	if err != nil {
		t.Fatalf("could not build issuance manifest: %v", err)
	}
	if issuanceManifest == nil {
		t.Fatalf("issuanceManifest is nil")
	}

	// sign the manifest and check it matches sample record
	signature, err := issuanceManifest.SignWithEd25519AndX5C(privateKey, keyID, certChain)
	if err != nil {
		t.Fatalf("could not sign issuance manifest: %v", err)
	}

	//t.Logf("signature: %v", signature)
	if signature != sampleIssuanceRequest.IssuanceManifestSignedContent {
		t.Errorf("signature does not match sample")
	}
}

func TestRecreateSampleIssuanceManifestRSA(t *testing.T) {

	sampleRecordPath := "testdata/transport-documents/HHL71800000-RSA.json"
	privateKeyPath := "testdata/transport-documents/keys/RSA-carrier.example.com.private.jwk"
	keyID := "testkid"
	certPath := "testdata/transport-documents/certs/RSA-carrier.example.com-fullchain.crt"

	data, err := os.ReadFile(sampleRecordPath)
	if err != nil {
		t.Fatalf("could not open %s: %v", sampleRecordPath, err)
	}

	privateKey, err := ReadRSAPrivateKeyFromJWKFile(privateKeyPath)
	if err != nil {
		t.Fatalf("Could not read private key file %s: %e", privateKeyPath, err)
	}

	certChain, err := ReadCertChainFromPEMFile(certPath)
	if err != nil {
		t.Fatalf("could not load cert chain from %s: %e", certPath, err)
	}

	var sampleIssuanceRequest struct {
		Document                  json.RawMessage `json:"document"`
		IssueTo                   json.RawMessage `json:"issueTo"`
		EBLVisualisationByCarrier struct {
			Name        string `json:"name"`
			Content     string `json:"content"`
			ContentType string `json:"contentType"`
		} `json:"eBLVisualisationByCarrier"`
		IssuanceManifestSignedContent string `json:"issuanceManifestSignedContent"`
	}
	err = json.Unmarshal(data, &sampleIssuanceRequest)
	if err != nil {
		t.Fatalf("could not marshal bl json: %v", err)
	}

	// recreate issuance manifest
	manifest := NewIssuanceManifestBuilder()
	manifest.WithDocument(sampleIssuanceRequest.Document)
	manifest.WithIssueTo(sampleIssuanceRequest.IssueTo)
	manifest.WithEBLVisualisation(sampleIssuanceRequest.EBLVisualisationByCarrier.Content) // content is already base64 encoded

	issuanceManifest, err := manifest.Build()
	if err != nil {
		t.Fatalf("could not build issuance manifest: %v", err)
	}
	if issuanceManifest == nil {
		t.Fatalf("issuanceManifest is nil")
	}

	// sign the manifest and check it matches sample record
	signature, err := issuanceManifest.SignWithRSAAndX5C(privateKey, keyID, certChain)
	if err != nil {
		t.Fatalf("could not sign issuance manifest: %v", err)
	}

	//t.Logf("signature: %v", signature)
	if signature != sampleIssuanceRequest.IssuanceManifestSignedContent {
		t.Errorf("signature does not match sample")
	}
}

// EnvelopeManifest tests TODO
