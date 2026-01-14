package crypto

import (
	"encoding/base64"
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
