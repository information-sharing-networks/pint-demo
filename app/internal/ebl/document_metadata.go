package ebl

// document_metadata.go provides functions for working with DCSA document metadata.
import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

// DocumentMetadata represents documents transferred via PINT and contains the document's checksum and other metadata.
// The document's binary content is not included in this structure and is sent separately.
type DocumentMetadata struct {

	// name: The name of the document
	Name string `json:"name"`

	// size: The size of the decoded document in bytes (not the Base64 encoded size)
	Size int64 `json:"size"`

	// mediaType: MIME type of the document
	MediaType string `json:"mediaType"`

	// documentChecksum: SHA-256 checksum of the document
	DocumentChecksum string `json:"documentChecksum"`
}

// ValidateStructure checks that all required fields are present per DCSA EBL_PINT specification.
func (d *DocumentMetadata) ValidateStructure() error {
	if d.Name == "" {
		return fmt.Errorf("name is required")
	}
	if d.Size <= 0 {
		return fmt.Errorf("size must be greater than 0")
	}
	if d.MediaType == "" {
		return fmt.Errorf("mediaType is required")
	}
	if d.DocumentChecksum == "" {
		return fmt.Errorf("documentChecksum is required")
	}
	return nil
}

// documentMetadataFromFile reads a file and creates DocumentMetadata with checksum.
// This is used for both eBL visualization and supporting documents.
func documentMetadataFromFile(filePath string) (*DocumentMetadata, error) {
	dir := filepath.Dir(filePath)
	filename := filepath.Base(filePath)

	// Read the file
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, WrapEnvelopeError(err, fmt.Sprintf("failed to open directory %s", dir))
	}
	defer root.Close()

	content, err := root.ReadFile(filename)
	if err != nil {
		return nil, WrapEnvelopeError(err, "failed to read file")
	}

	// Detect content type (defaults to application/octet-stream if no match)
	contentType := http.DetectContentType(content)

	// Calculate SHA-256 checksum of the binary content
	checksum, err := crypto.Hash(content)
	if err != nil {
		return nil, WrapEnvelopeError(err, "failed to calculate checksum")
	}

	return &DocumentMetadata{
		Name:             filename,
		Size:             int64(len(content)),
		MediaType:        contentType,
		DocumentChecksum: checksum,
	}, nil
}
