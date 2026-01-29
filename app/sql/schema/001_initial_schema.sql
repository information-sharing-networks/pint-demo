-- +goose Up

-- Envelopes table - tracks envelope transfer state
CREATE TABLE envelopes (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    envelope_reference UUID NOT NULL UNIQUE,  -- Receiver-generated identifier returned to sender for subsequent API calls
    transport_document_reference TEXT NOT NULL,  -- Sender's B/L number (extracted from transportDocument JSON for indexing)
    transport_document_checksum TEXT NOT NULL,  -- SHA-256 checksum of the canonical JSON transportDocument
    transport_document JSONB NOT NULL,  -- The eBL document
    envelope_manifest_signed_content TEXT NOT NULL,  -- JWS-signed EnvelopeManifest
    last_transfer_chain_entry_signed_content TEXT NOT NULL,  -- JWS-signed last transfer chain entry
    last_transfer_chain_entry_checksum TEXT NOT NULL,  -- SHA-256 checksum of last_transfer_chain_entry_signed_content 
    sender_platform TEXT NOT NULL,  -- eBL platform that sent this envelope 
    sender_ebl_platform TEXT,  -- Optional: eBL platform identifier from JWS kid
    trust_level TEXT NOT NULL,  -- Certificate trust level: EV, OV, or DV
    state TEXT NOT NULL,
    response_code TEXT,
    CONSTRAINT envelopes_state_check CHECK (state IN (
        'PENDING',      -- Transfer started (201), waiting for additional documents
        'ACCEPTED',     -- Transfer accepted (200 with RECE)
        'DUPLICATE',    -- Duplicate detected (200 with DUPE)
        'REJECTED'      -- Transfer rejected (422 with BSIG/BENV or 409 with DISE)
    )),
    CONSTRAINT envelopes_response_code_check CHECK (response_code IS NULL OR response_code IN (
        'RECE',  -- Received and accepted
        'DUPE',  -- Duplicate (already received)
        'BENV',  -- Bad envelope
        'BSIG',  -- Bad signature
        'MDOC',  -- Missing documents
        'DISE',  -- Disagreement on envelope state
        'INCD',  -- Inconsistent document
        'INT2'    -- Internal error
    )),
    CONSTRAINT envelopes_trust_level_check CHECK (trust_level IN ('EV', 'OV', 'DV'))
);

CREATE INDEX idx_envelopes_reference ON envelopes(envelope_reference);
CREATE INDEX idx_envelopes_transport_document_reference ON envelopes(transport_document_reference);
CREATE INDEX idx_envelopes_transport_document_checksum ON envelopes(transport_document_checksum);
CREATE INDEX idx_envelopes_last_chain_entry_checksum ON envelopes(last_transfer_chain_entry_checksum);
CREATE INDEX idx_envelopes_state ON envelopes(state);
CREATE INDEX idx_envelopes_created_at ON envelopes(created_at DESC);

-- Additional documents table - tracks supporting documents and eBL visualizations
CREATE TABLE additional_documents (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    envelope_id UUID NOT NULL,
    document_checksum TEXT NOT NULL,
    document_content BYTEA NOT NULL,
    media_type TEXT NOT NULL,
    is_ebl_visualisation BOOL NOT NULL,
    CONSTRAINT additional_documents_unique_doc_per_envelope UNIQUE(envelope_id, document_checksum),
    CONSTRAINT fk_additional_documents_envelope FOREIGN KEY (envelope_id)
        REFERENCES envelopes(id)
        ON DELETE CASCADE
);

CREATE INDEX idx_additional_docs_envelope ON additional_documents(envelope_id);
CREATE INDEX idx_additional_docs_checksum ON additional_documents(document_checksum);

-- Transfer chain entries table - stores the complete transfer chain history
CREATE TABLE transfer_chain_entries (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    envelope_id UUID NOT NULL,
    signed_content TEXT NOT NULL,
    sequence BIGINT NOT NULL,
    CONSTRAINT transfer_chain_entries_unique_sequence_per_envelope UNIQUE(envelope_id, sequence),
    CONSTRAINT fk_transfer_chain_entries_envelope FOREIGN KEY (envelope_id)
        REFERENCES envelopes(id)
        ON DELETE CASCADE
);

CREATE INDEX idx_transfer_chain_envelope ON transfer_chain_entries(envelope_id, sequence);

-- +goose Down

DROP TABLE IF EXISTS transfer_chain_entries CASCADE;
DROP TABLE IF EXISTS additional_documents CASCADE;
DROP TABLE IF EXISTS envelopes CASCADE;

