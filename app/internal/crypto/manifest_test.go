package crypto

import (
	"encoding/base64"
	"testing"
)

// TODO - tests for envelopeTransferChain and envelopeManifestSignedContent
// todo use the real test data from testdata/transport-documents/HHL71800000.json as a sanity check after the unit tests
// Test data for issuance manifest tests
var (
	testDocument                         = []byte(`{"transportDocumentReference":"MAEU123456"}`)
	testIssueTo                          = []byte(`{"partyName":"Test Company"}`)
	testEblVisualisationByCarrier        = []byte(`mock pdf binary content here`)
	testEblVisualisationByCarrierContent = []byte(base64.StdEncoding.EncodeToString(testEblVisualisationByCarrier))
)

func TestIssuanceManifestBuilderNew(t *testing.T) {
	tests := []struct {
		name          string
		document      []byte
		issueTo       []byte
		visualization []byte
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
			visualization: []byte(base64.StdEncoding.EncodeToString([]byte{0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34})),
			wantErr:       false,
		},
		{
			name:          "invalid - raw binary visualization (not base64)",
			document:      testDocument,
			issueTo:       testIssueTo,
			visualization: []byte{0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34}, // Raw PDF binary content
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
			if tt.visualization != nil {
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
			if tt.visualization != nil && (manifest.EBLVisualisationByCarrierChecksum == nil || *manifest.EBLVisualisationByCarrierChecksum == "") {
				t.Error("EBLVisualisationByCarrierChecksum should set")
			}
			if tt.visualization != nil && len(*manifest.EBLVisualisationByCarrierChecksum) != 64 {
				t.Errorf("EBLVisualisationByCarrierChecksum length = %d, want 64",
					len(*manifest.EBLVisualisationByCarrierChecksum))
			}
		})
	}
}

// EnvelopeManifest tests TODO
