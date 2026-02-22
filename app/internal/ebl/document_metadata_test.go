package ebl

import (
	"testing"
)

func TestDocumentMetadataFromFile(t *testing.T) {
	tests := []struct {
		name        string
		filePath    string
		wantErr     bool
		wantName    string
		wantSize    int64
		wantType    string
		wantHash    string
		expectedErr string
	}{
		{
			name:        "valid pdf",
			filePath:    "../../test/testdata/pint-transfers/HHL71800000-invoice.pdf",
			wantErr:     false,
			expectedErr: "",
			wantName:    "HHL71800000-invoice.pdf",
			wantSize:    13563,
			wantType:    "application/pdf",
			wantHash:    "6e270fd7f8694ce33b1c4bbb6fd810a68ecd5967a81a660888aced555a2a8e98",
		},
		{
			name:        "valid png",
			filePath:    "../../test/testdata/pint-transfers/HHL71800000-not-found",
			wantErr:     true,
			expectedErr: "failed to read file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metatadata, err := documentMetadataFromFile(tt.filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("documentMetadataFromFile() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil {
				if tt.expectedErr != "" && !contains(err.Error(), tt.expectedErr) {
					t.Errorf("expected error to contain %q, got %q", tt.expectedErr, err.Error())
				}
				return
			}

			if metatadata.Name != tt.wantName {
				t.Errorf("documentMetadataFromFile() name = %v, want %v", metatadata.Name, tt.wantName)
			}
			if metatadata.Size != tt.wantSize {
				t.Errorf("documentMetadataFromFile() size = %v, want %v", metatadata.Size, tt.wantSize)
			}
			if metatadata.MediaType != tt.wantType {
				t.Errorf("documentMetadataFromFile() mediaType = %v, want %v", metatadata.MediaType, tt.wantType)
			}
			if metatadata.DocumentChecksum != tt.wantHash {
				t.Errorf("documentMetadataFromFile() hash = %v, want %v", metatadata.DocumentChecksum, tt.wantHash)
			}
		})
	}
}
