package crypto

import (
	"testing"
)

var (
	validTransportDocument = []byte(`{"transportDocumentReference":"MAEU123456","shippingInstructionReference":"SI123456"}`)
	validLastTransferChain = "eyJhbGciOiJFZERTQSIsImtpZCI6InRlc3RraWQifQ.eyJ0cmFuc3BvcnREb2N1bWVudENoZWNrc3VtIjoiYWJjMTIzIn0.c2lnbmF0dXJl" // mock JWS
	validEblVisualization  = &DocumentMetadata{
		Name:             "ebl.pdf",
		Size:             100,
		MediaType:        "application/pdf",
		DocumentChecksum: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
	}
	validSupportingDocuments = []DocumentMetadata{
		{
			Name:             "invoice.pdf",
			Size:             100,
			MediaType:        "application/pdf",
			DocumentChecksum: "b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		},
		{
			Name:             "packing-list.pdf",
			Size:             100,
			MediaType:        "application/pdf",
			DocumentChecksum: "c1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		},
	}
)

func TestEnvelopeManifestBuilder(t *testing.T) {
	tests := []struct {
		name                string
		transportDocument   []byte
		lastTransferChain   string
		eblVisualisation    *DocumentMetadata
		supportingDocuments []DocumentMetadata
		wantErr             bool
		expectedErrContains string
	}{
		{
			name:              "valid - minimal (no optional fields)",
			transportDocument: validTransportDocument,
			lastTransferChain: validLastTransferChain,
			wantErr:           false,
		},
		{
			name:              "valid - with eBL visualisation",
			transportDocument: validTransportDocument,
			lastTransferChain: validLastTransferChain,
			eblVisualisation:  validEblVisualization,
			wantErr:           false,
		},
		{
			name:                "valid - with supporting documents",
			transportDocument:   validTransportDocument,
			lastTransferChain:   validLastTransferChain,
			supportingDocuments: validSupportingDocuments,
			wantErr:             false,
		},
		{
			name:                "valid - with both eBL visualisation and supporting documents",
			transportDocument:   validTransportDocument,
			lastTransferChain:   validLastTransferChain,
			eblVisualisation:    validEblVisualization,
			supportingDocuments: validSupportingDocuments,
			wantErr:             false,
		},
		{
			name:                "missing transport document",
			transportDocument:   nil,
			lastTransferChain:   validLastTransferChain,
			wantErr:             true,
			expectedErrContains: "transport document is required",
		},
		{
			name:                "missing last transfer chain",
			transportDocument:   validTransportDocument,
			lastTransferChain:   "",
			wantErr:             true,
			expectedErrContains: "last transfer chain entry is required",
		},
		{
			name:                "invalid transport document JSON",
			transportDocument:   []byte(`invalid json`),
			lastTransferChain:   validLastTransferChain,
			wantErr:             true,
			expectedErrContains: "failed to canonicalize",
		},
		{
			name:              "eBL visualisation missing name",
			transportDocument: validTransportDocument,
			lastTransferChain: validLastTransferChain,
			eblVisualisation: &DocumentMetadata{
				Name:             "",
				Size:             12345,
				MediaType:        "application/pdf",
				DocumentChecksum: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			},
			wantErr:             true,
			expectedErrContains: "name is required",
		},
		{
			name:              "eBL visualisation missing size",
			transportDocument: validTransportDocument,
			lastTransferChain: validLastTransferChain,
			eblVisualisation: &DocumentMetadata{
				Name:             "ebl.pdf",
				Size:             0,
				MediaType:        "application/pdf",
				DocumentChecksum: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			},
			wantErr:             true,
			expectedErrContains: "size must be greater than 0",
		},
		{
			name:              "eBL visualisation missing mediaType",
			transportDocument: validTransportDocument,
			lastTransferChain: validLastTransferChain,
			eblVisualisation: &DocumentMetadata{
				Name:             "ebl.pdf",
				Size:             12345,
				MediaType:        "",
				DocumentChecksum: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			},
			wantErr:             true,
			expectedErrContains: "mediaType is required",
		},
		{
			name:              "eBL visualisation missing documentChecksum",
			transportDocument: validTransportDocument,
			lastTransferChain: validLastTransferChain,
			eblVisualisation: &DocumentMetadata{
				Name:             "ebl.pdf",
				Size:             12345,
				MediaType:        "application/pdf",
				DocumentChecksum: "",
			},
			wantErr:             true,
			expectedErrContains: "documentChecksum is required",
		},
		{
			name:              "supporting document missing name",
			transportDocument: validTransportDocument,
			lastTransferChain: validLastTransferChain,
			supportingDocuments: []DocumentMetadata{
				{
					Name:             "",
					Size:             5000,
					MediaType:        "application/pdf",
					DocumentChecksum: "b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
				},
			},
			wantErr:             true,
			expectedErrContains: "supporting document 0: name is required",
		},
		{
			name:              "supporting document missing size",
			transportDocument: validTransportDocument,
			lastTransferChain: validLastTransferChain,
			supportingDocuments: []DocumentMetadata{
				{
					Name:             "invoice.pdf",
					Size:             0,
					MediaType:        "application/pdf",
					DocumentChecksum: "b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
				},
			},
			wantErr:             true,
			expectedErrContains: "supporting document 0: size must be greater than 0",
		},
		{
			name:              "supporting document missing mediaType",
			transportDocument: validTransportDocument,
			lastTransferChain: validLastTransferChain,
			supportingDocuments: []DocumentMetadata{
				{
					Name:             "invoice.pdf",
					Size:             5000,
					MediaType:        "",
					DocumentChecksum: "b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
				},
			},
			wantErr:             true,
			expectedErrContains: "supporting document 0: mediaType is required",
		},
		{
			name:              "supporting document missing documentChecksum",
			transportDocument: validTransportDocument,
			lastTransferChain: validLastTransferChain,
			supportingDocuments: []DocumentMetadata{
				{
					Name:             "invoice.pdf",
					Size:             5000,
					MediaType:        "application/pdf",
					DocumentChecksum: "",
				},
			},
			wantErr:             true,
			expectedErrContains: "supporting document 0: documentChecksum is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewEnvelopeManifestBuilder()
			if tt.transportDocument != nil {
				builder.WithTransportDocument(tt.transportDocument)
			}
			if tt.lastTransferChain != "" {
				builder.WithLastTransferChainEntry(tt.lastTransferChain)
			}
			if tt.eblVisualisation != nil {
				builder.WithEBLVisualisationByCarrier(*tt.eblVisualisation)
			}
			if len(tt.supportingDocuments) > 0 {
				builder.WithSupportingDocuments(tt.supportingDocuments)
			}

			manifest, err := builder.Build()
			if (err != nil) != tt.wantErr {
				t.Errorf("EnvelopeManifestBuilder.Build() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.expectedErrContains != "" && err != nil {
					if !contains(err.Error(), tt.expectedErrContains) {
						t.Errorf("Expected error to contain %q, got %q", tt.expectedErrContains, err.Error())
					}
				}
				return
			}

			// Ensure manifest is not nil before accessing fields
			if manifest == nil {
				t.Fatal("Build() returned nil manifest without error")
			}

			// Verify required checksums
			if manifest.TransportDocumentChecksum == "" {
				t.Error("TransportDocumentChecksum is empty")
			}
			if len(manifest.TransportDocumentChecksum) != 64 {
				t.Errorf("TransportDocumentChecksum length = %d, want 64 (SHA-256 hex)", len(manifest.TransportDocumentChecksum))
			}
			if manifest.LastEnvelopeTransferChainEntrySignedContentChecksum == "" {
				t.Error("LastEnvelopeTransferChainEntrySignedContentChecksum is empty")
			}
			if len(manifest.LastEnvelopeTransferChainEntrySignedContentChecksum) != 64 {
				t.Errorf("LastEnvelopeTransferChainEntrySignedContentChecksum length = %d, want 64 (SHA-256 hex)", len(manifest.LastEnvelopeTransferChainEntrySignedContentChecksum))
			}

			// Verify optional fields
			if tt.eblVisualisation != nil {
				if manifest.EBLVisualisationByCarrier == nil {
					t.Error("EBLVisualisationByCarrier should be set")
				} else {
					if manifest.EBLVisualisationByCarrier.Name != tt.eblVisualisation.Name {
						t.Errorf("EBLVisualisationByCarrier.Name = %s, want %s", manifest.EBLVisualisationByCarrier.Name, tt.eblVisualisation.Name)
					}
					if manifest.EBLVisualisationByCarrier.DocumentChecksum != tt.eblVisualisation.DocumentChecksum {
						t.Errorf("EBLVisualisationByCarrier.DocumentChecksum = %s, want %s", manifest.EBLVisualisationByCarrier.DocumentChecksum, tt.eblVisualisation.DocumentChecksum)
					}
				}
			} else {
				if manifest.EBLVisualisationByCarrier != nil {
					t.Error("EBLVisualisationByCarrier should be nil")
				}
			}

			if len(tt.supportingDocuments) > 0 {
				if len(manifest.SupportingDocuments) != len(tt.supportingDocuments) {
					t.Errorf("SupportingDocuments length = %d, want %d", len(manifest.SupportingDocuments), len(tt.supportingDocuments))
				}
				for i, doc := range tt.supportingDocuments {
					if manifest.SupportingDocuments[i].Name != doc.Name {
						t.Errorf("SupportingDocuments[%d].Name = %s, want %s", i, manifest.SupportingDocuments[i].Name, doc.Name)
					}
					if manifest.SupportingDocuments[i].DocumentChecksum != doc.DocumentChecksum {
						t.Errorf("SupportingDocuments[%d].DocumentChecksum = %s, want %s", i, manifest.SupportingDocuments[i].DocumentChecksum, doc.DocumentChecksum)
					}
				}
			} else {
				if len(manifest.SupportingDocuments) > 0 {
					t.Error("SupportingDocuments should be empty")
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && stringContains(s, substr)))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
