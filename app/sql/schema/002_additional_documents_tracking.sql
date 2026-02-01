-- +goose Up

-- Drop the old additional_documents table and recreate with proper tracking fields
DROP TABLE IF EXISTS additional_documents CASCADE;

-- Additional documents table - tracks expected and received supporting documents and eBL visualizations
CREATE TABLE additional_documents (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    envelope_id UUID NOT NULL,
    
    -- Document identification (from manifest)
    document_checksum TEXT NOT NULL,  -- SHA-256 checksum 
    document_name TEXT NOT NULL,      -- Filename from manifest
    document_size BIGINT NOT NULL,    -- Size in bytes (decoded, not base64)
    media_type TEXT NOT NULL,         -- MIME type (e.g., application/pdf)
    is_ebl_visualisation BOOL NOT NULL,  -- True if this is the eBLVisualisationByCarrier document
    
    -- Document content (NULL until received)
    document_content BYTEA,           -- Binary content (base64-decoded)
    
    -- Tracking fields
    received_at TIMESTAMP WITH TIME ZONE,      -- When the document was successfully received
    last_error_at TIMESTAMP WITH TIME ZONE,    -- Last time a transfer attempt failed
    last_error_message TEXT,                   -- Last error message
    
    CONSTRAINT additional_documents_unique_doc_per_envelope UNIQUE(envelope_id, document_checksum),
    CONSTRAINT fk_additional_documents_envelope FOREIGN KEY (envelope_id)
        REFERENCES envelopes(id)
        ON DELETE CASCADE,
    
    -- If document_content is present, received_at must also be present
    CONSTRAINT additional_documents_received_check CHECK (
        (document_content IS NULL AND received_at IS NULL) OR
        (document_content IS NOT NULL AND received_at IS NOT NULL)
    )
);

CREATE INDEX idx_additional_docs_envelope ON additional_documents(envelope_id);
CREATE INDEX idx_additional_docs_checksum ON additional_documents(document_checksum);
CREATE INDEX idx_additional_docs_received ON additional_documents(envelope_id, received_at) WHERE received_at IS NULL;

-- +goose Down

DROP TABLE IF EXISTS additional_documents CASCADE;