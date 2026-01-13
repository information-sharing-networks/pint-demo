package crypto

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// Test data for issuance manifest tests
var (
	validDocument      = []byte(`{"transportDocumentReference":"MAEU123456"}`)
	validIssueTo       = []byte(`{"partyName":"Test Company"}`)
	validBinaryContent = []byte(`mock pdf binary content here`)
	validContentBase64 = base64.StdEncoding.EncodeToString(validBinaryContent)
)

func TestIssuanceManifestBuilderNew(t *testing.T) {
	tests := []struct {
		name                      string
		document                  []byte
		issueTo                   []byte
		eBLVisualisationByCarrier *EBLVisualisationByCarrier
		wantErr                   bool
	}{
		{
			name:     "valid - no visualization",
			document: validDocument,
			issueTo:  validIssueTo,
			wantErr:  false,
		},
		{
			name:     "valid - including visualization",
			document: validDocument,
			issueTo:  validIssueTo,
			eBLVisualisationByCarrier: &EBLVisualisationByCarrier{
				Name:        "test.pdf",
				Content:     validContentBase64,
				ContentType: "application/pdf",
			},
			wantErr: false,
		},
		{
			name:     "missing document",
			document: nil,
			issueTo:  validIssueTo,
			eBLVisualisationByCarrier: &EBLVisualisationByCarrier{
				Name:        "test.pdf",
				Content:     validContentBase64,
				ContentType: "application/pdf",
			},
			wantErr: true,
		},
		{
			name:     "missing issueTo",
			document: validDocument,
			eBLVisualisationByCarrier: &EBLVisualisationByCarrier{
				Name:        "test.pdf",
				Content:     validContentBase64,
				ContentType: "application/pdf",
			},
			issueTo: nil,
			wantErr: true,
		},
		{
			name:     "invalid document json",
			document: []byte(`invalid json`),
			issueTo:  validIssueTo,
			eBLVisualisationByCarrier: &EBLVisualisationByCarrier{
				Name:        "test.pdf",
				Content:     validContentBase64,
				ContentType: "application/pdf",
			},
			wantErr: true,
		},
		{
			name:     "invalid issueTo json",
			document: validDocument,
			eBLVisualisationByCarrier: &EBLVisualisationByCarrier{
				Name:        "test.pdf",
				Content:     validContentBase64,
				ContentType: "application/pdf",
			},
			issueTo: []byte(`invalid json`),
			wantErr: true,
		},
		{
			name:     "valid base64 encoded visualization",
			document: validDocument,
			issueTo:  validIssueTo,
			eBLVisualisationByCarrier: &EBLVisualisationByCarrier{
				Name:        "test.pdf",
				Content:     validContentBase64,
				ContentType: "application/pdf",
			},
			wantErr: false,
		},
		{
			name:     "invalid - raw binary visualization (not base64)",
			document: validDocument,
			issueTo:  validIssueTo,
			eBLVisualisationByCarrier: &EBLVisualisationByCarrier{
				Name:        "test.pdf",
				Content:     string([]byte{0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34}), // Raw binary as string (not base64)
				ContentType: "application/pdf",
			},
			wantErr: true,
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
			if tt.eBLVisualisationByCarrier != nil {
				builder.WithEBLVisualisation(tt.eBLVisualisationByCarrier)
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
			if tt.eBLVisualisationByCarrier != nil && (manifest.EBLVisualisationByCarrierChecksum == nil || *manifest.EBLVisualisationByCarrierChecksum == "") {
				t.Error("EBLVisualisationByCarrierChecksum should be set")
			}
		})
	}
}

// sanity check to confirm we can correctly recreate the manually computed signatures in
// HHL71800000-ed25519.json and HHL71800000-rsa.json
func TestRecreateSampleIssuanceManifestEd25519(t *testing.T) {

	sampleRecordPath := "testdata/transport-documents/HHL71800000-ed25519.json"
	privateKeyPath := "testdata/keys/ed25519-carrier.example.com.private.jwk"
	keyID := "testkid"
	certPath := "testdata/certs/ed25519-carrier.example.com-fullchain.crt"

	data, err := os.ReadFile(sampleRecordPath)
	if err != nil {
		t.Fatalf("could not open %s: %v", sampleRecordPath, err)
	}

	privateKey, err := ReadEd25519PrivateKeyFromJWKFile("testdata/keys", "ed25519-carrier.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Could not read private key file %s: %e", privateKeyPath, err)
	}

	certChain, err := ReadCertChainFromPEMFile("testdata/certs", "ed25519-carrier.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("could not load cert chain from %s: %e", certPath, err)
	}

	var sampleIssuanceRequest struct {
		Document                      json.RawMessage            `json:"document"`
		IssueTo                       json.RawMessage            `json:"issueTo"`
		EBLVisualisationByCarrier     *EBLVisualisationByCarrier `json:"eBLVisualisationByCarrier"`
		IssuanceManifestSignedContent string                     `json:"issuanceManifestSignedContent"`
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
	manifest.WithEBLVisualisation(sampleIssuanceRequest.EBLVisualisationByCarrier)

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
	if string(signature) != sampleIssuanceRequest.IssuanceManifestSignedContent {
		t.Errorf("signature does not match sample")
	}
}

func TestRecreateSampleIssuanceManifestRSA(t *testing.T) {

	sampleRecordPath := "testdata/transport-documents/HHL71800000-rsa.json"
	privateKeyPath := "testdata/keys/rsa-carrier.example.com.private.jwk"
	keyID := "testkid"
	certPath := "testdata/certs/rsa-carrier.example.com-fullchain.crt"

	data, err := os.ReadFile(sampleRecordPath)
	if err != nil {
		t.Fatalf("could not open %s: %v", sampleRecordPath, err)
	}

	privateKey, err := ReadRSAPrivateKeyFromJWKFile("testdata/keys", "rsa-carrier.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Could not read private key file %s: %e", privateKeyPath, err)
	}

	certChain, err := ReadCertChainFromPEMFile("testdata/certs", "rsa-carrier.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("could not load cert chain from %s: %e", certPath, err)
	}

	var sampleIssuanceRequest struct {
		Document                      json.RawMessage            `json:"document"`
		IssueTo                       json.RawMessage            `json:"issueTo"`
		EBLVisualisationByCarrier     *EBLVisualisationByCarrier `json:"eBLVisualisationByCarrier"`
		IssuanceManifestSignedContent string                     `json:"issuanceManifestSignedContent"`
	}
	err = json.Unmarshal(data, &sampleIssuanceRequest)
	if err != nil {
		t.Fatalf("could not marshal bl json: %v", err)
	}

	// recreate issuance manifest
	manifest := NewIssuanceManifestBuilder()
	manifest.WithDocument(sampleIssuanceRequest.Document)
	manifest.WithIssueTo(sampleIssuanceRequest.IssueTo)
	manifest.WithEBLVisualisation(sampleIssuanceRequest.EBLVisualisationByCarrier) // content is already base64 encoded

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
	if string(signature) != sampleIssuanceRequest.IssuanceManifestSignedContent {
		t.Errorf("signature does not match sample")
	}
}
