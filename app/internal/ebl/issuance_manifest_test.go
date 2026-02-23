package ebl

import (
	"testing"
)

// Test data for issuance manifest tests
var (
	validDocument               = TransportDocumentChecksum(`{"transportDocumentReference":"MAEU123456"}`)
	validIssueTo                = IssueToChecksum(`{"partyName":"Test Company"}`)
	validVisualisationByCarrier = EBLVisualisationByCarrierChecksum(`d870e9d766ca0b9087f86d8d05ea6bf48d166717c0bf375efff54cedeb3d00b8`)
)

func TestIssuanceManifestBuilderNew(t *testing.T) {
	tests := []struct {
		name                              string
		documentChecksum                  TransportDocumentChecksum
		issueToChecksum                   IssueToChecksum
		eBLVisualisationByCarrierChecksum EBLVisualisationByCarrierChecksum
		wantErr                           bool
	}{
		{
			name:             "valid - no Visualisation",
			documentChecksum: validDocument,
			issueToChecksum:  validIssueTo,
			wantErr:          false,
		},
		{
			name:                              "valid - including Visualisation",
			documentChecksum:                  validDocument,
			issueToChecksum:                   validIssueTo,
			eBLVisualisationByCarrierChecksum: validVisualisationByCarrier,
			wantErr:                           false,
		},
		{
			name:                              "missing transport document",
			issueToChecksum:                   validIssueTo,
			eBLVisualisationByCarrierChecksum: validVisualisationByCarrier,
			wantErr:                           true,
		},
		{
			name:                              "missing issueTo",
			documentChecksum:                  validDocument,
			eBLVisualisationByCarrierChecksum: validVisualisationByCarrier,
			wantErr:                           true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewIssuanceManifestBuilder()
			if tt.documentChecksum != "" {
				builder.WithDocumentChecksum(tt.documentChecksum)
			}
			if tt.issueToChecksum != "" {
				builder.WithIssueTo(tt.issueToChecksum)
			}
			if tt.eBLVisualisationByCarrierChecksum != "" {
				builder.WitheBLVisualisationByCarrierChecksum(tt.eBLVisualisationByCarrierChecksum)
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
			if manifest.IssueToChecksum == "" {
				t.Error("IssueToChecksum is empty")
			}
			if tt.eBLVisualisationByCarrierChecksum != "" && (manifest.EBLVisualisationByCarrierChecksum == nil || *manifest.EBLVisualisationByCarrierChecksum == "") {
				t.Error("EBLVisualisationByCarrierChecksum should be set")
			}
		})
	}
}
