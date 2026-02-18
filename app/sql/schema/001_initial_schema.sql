-- +goose Up

-- transport_documents - Registry of unique eBL documents (transport documents) seen by this platform.
CREATE TABLE transport_documents (
    checksum TEXT PRIMARY KEY, -- SHA-256 checksum of canonical JSON (per DCSA spec)
    content JSONB NOT NULL, -- The actual transport document content
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
    first_received_from_platform_code TEXT NOT NULL -- DCSA platform code that first sent this eBL to us (e.g., "WAVE", "CARX")
);

-- envelopes - each row represents an transfer of a eBL received by this platform
-- The same eBL can be transferred multiple times and go back and forth between platforms.
-- Each transfer has a unique chain of transactions (transfer chain entries) that are cryptographically linked
-- and uniquely identified by the last_transfer_chain_entry_signed_content_checksum
CREATE TABLE envelopes (
    -- Used as an opaque ID ('envelope_reference') in API responses 
    id UUID PRIMARY KEY, 

    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- envelope_state - the state of the eBL at the time of the transfer.
    envelope_state TEXT NOT NULL CHECK (envelope_state IN ('ISSUE', 'TRANSFER', 'ENDORSE', 'ENDORSE_TO_ORDER', 'BLANK_ENDORSE', 'SIGN', 'SURRENDER_FOR_AMENDMENT', 'SURRENDER_FOR_DELIVERY')),

    -- Links to the eBL document being transferred
    transport_document_checksum TEXT NOT NULL,

    -- SHA-256 checksum of the payload of the last transfer chain entry JWS token
    -- this uniquely identifies a specific transfer attempt and is used to detect duplicate transfer attempts. 
    -- (id/envelope_reference is a proxy for this field).
    last_transfer_chain_entry_signed_content_payload_checksum TEXT NOT NULL UNIQUE, 

    -- this is the original checksum of the jws token of the last transfer chain entry.
    -- Note it is not guaranteed that this will be sent again on retries, 
    -- since the sender may use non-deterministic signature algorithms (e.g PS256), in which case the
    -- checksum will change even if they use the same payload and private key.
    last_transfer_chain_entry_signed_content_checksum TEXT NOT NULL, 

    sent_by_platform_code TEXT NOT NULL, -- DCSA platform code of sender (e.g., "WAVE", "CARX")

    -- Signed content (JWS tokens) - kept for audit trail
    envelope_manifest_signed_content TEXT NOT NULL, -- JWS of EnvelopeManifest
    last_transfer_chain_entry_signed_content TEXT NOT NULL, -- JWS of last entry 

    -- Trust level from certificate validation (1=NoX5C, 2=DV, 3=EV/OV)
    trust_level INTEGER NOT NULL CHECK (trust_level IN (1, 2, 3)),

    -- Transfer acceptance tracking (NULL = not yet accepted, timestamp = when transfer was accepted with RECE)
    accepted_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_envelopes_transport_document FOREIGN KEY (transport_document_checksum)
        REFERENCES transport_documents(checksum)
        ON DELETE CASCADE
);
CREATE INDEX idx_envelopes_transport_document ON envelopes(transport_document_checksum);

-- transfer_chain_entries - contains the transfer chain entries for all eBLs, linked by transport_document_checksum.
-- This enables (limited) DISE (dispute) detection by comparing the transfer chain entries of two platforms for the same eBL.
-- The chain forms a linked list via previous_entry_checksum, allowing reconstruction.
-- of the full history by walking backwards from any entry.
--
-- Note the calling application is responsible for ensuring this table does not contain forks or broken chains.
CREATE TABLE transfer_chain_entries (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Links to the eBL document (CRITICAL for DISE detection)
    transport_document_checksum TEXT NOT NULL,

    -- Links to the envelope/transfer that brought this entry to our platform
    envelope_id UUID NOT NULL,

    -- The signed content and its checksum
    signed_content TEXT NOT NULL, -- JWS of EnvelopeTransferChainEntry
    entry_checksum TEXT NOT NULL UNIQUE, -- SHA-256 of signed_content

    -- Blockchain-like linking
    previous_entry_checksum TEXT, -- NULL for first entry (ISSUE transaction)

    -- Position in the chain for this envelope
    sequence INTEGER NOT NULL,

    CONSTRAINT fk_transfer_chain_entries_envelope FOREIGN KEY (envelope_id)
        REFERENCES envelopes(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_transfer_chain_entries_transport_document FOREIGN KEY (transport_document_checksum)
        REFERENCES transport_documents(checksum)
        ON DELETE CASCADE,
    CONSTRAINT fk_transfer_chain_entries_previous FOREIGN KEY (previous_entry_checksum)
        REFERENCES transfer_chain_entries(entry_checksum)
        ON DELETE RESTRICT, -- Don't allow deleting entries that are referenced
    CONSTRAINT unique_sequence_per_envelope UNIQUE(envelope_id, sequence)
);
CREATE INDEX idx_transfer_chain_entries_transport_document ON transfer_chain_entries(transport_document_checksum);
CREATE INDEX idx_transfer_chain_entries_envelope ON transfer_chain_entries(envelope_id, sequence);

-- additional_documents - Tracks expected and received additional documents (supporting docs and eBL visualisation)
-- for each envelope transfer. Documents are scoped to a specific transfer session.
CREATE TABLE additional_documents (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Links to the envelope/transfer
    envelope_id UUID NOT NULL,

    -- Document metadata (from EnvelopeManifest)
    document_checksum TEXT NOT NULL, -- SHA-256 of document content
    document_name TEXT NOT NULL,
    expected_size BIGINT NOT NULL,
    media_type TEXT NOT NULL,
    is_ebl_visualisation BOOLEAN NOT NULL DEFAULT FALSE,

    -- Document content (NULL until received via PUT endpoint)
    document_content BYTEA, -- Binary content
    received_at TIMESTAMP WITH TIME ZONE, -- When successfully received

    CONSTRAINT fk_additional_documents_envelope FOREIGN KEY (envelope_id)
        REFERENCES envelopes(id)
        ON DELETE CASCADE,
    CONSTRAINT unique_document_per_envelope UNIQUE(envelope_id, document_checksum),
    CONSTRAINT content_and_received_together CHECK (
        (document_content IS NULL AND received_at IS NULL) OR
        (document_content IS NOT NULL AND received_at IS NOT NULL)
    )
);
CREATE INDEX idx_additional_documents_envelope ON additional_documents(envelope_id);

COMMENT ON TABLE transport_documents IS 'Registry of unique eBL documents. Same eBL can be transferred multiple times.';
COMMENT ON TABLE envelopes IS 'Each row = one transfer session. Multiple rows can exist for same transport_document_checksum.';
COMMENT ON TABLE transfer_chain_entries IS 'Each transfer has a unique chain of transactions that are cryptographically linked and uniquely identified by the last_transfer_chain_entry_signed_content_checksum';
COMMENT ON TABLE additional_documents IS 'Expected and received additional documents, scoped to specific transfer sessions.';

COMMENT ON COLUMN envelopes.last_transfer_chain_entry_signed_content_checksum IS 'UNIQUE constraint prevents duplicate transfers of same chain.';

-- +goose Down
DROP TABLE IF EXISTS additional_documents CASCADE;
DROP TABLE IF EXISTS transfer_chain_entries CASCADE;
DROP TABLE IF EXISTS envelopes CASCADE;
DROP TABLE IF EXISTS transport_documents CASCADE;
