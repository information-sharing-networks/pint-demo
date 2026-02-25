-- +goose Up    

-- transport_document_latest - view showing the latest action for each eBL document
CREATE VIEW transport_document_state AS
    SELECT id envelope_id,
        transport_document_checksum,
        action_code,
        sent_by_platform_code,
        received_by_platform_code,
        created_at,
        (accepted_at IS NOT NULL)::bool AS accepted,
        accepted_at 
    FROM envelopes
    WHERE id IN (
        SELECT id FROM envelopes e
        WHERE created_at = (
            SELECT MAX(created_at)
            FROM envelopes 
            WHERE transport_document_checksum = e.transport_document_checksum
        )
    );

-- transport_document_possession - view showing the latest accepted possessor for each eBL document


-- transport_document_latest - view showing the platform that, according to the stored transfer chain, is the current possessor of each eBL document
-- to possess the document, the platform was either:
-- issued it by the carrier 
-- transfered it from the previous possessor
-- received during a surrender action
CREATE VIEW transport_document_possessor AS
    SELECT id envelope_id,
        transport_document_checksum,
        action_code,
        received_by_platform_code AS possessor_platform_code,
        created_at,
        accepted_at 
    FROM envelopes
    WHERE id IN (
        SELECT id FROM envelopes e
        WHERE created_at = (
            SELECT MAX(created_at)
            FROM envelopes 
            WHERE transport_document_checksum = e.transport_document_checksum
        )
        AND accepted_at IS NOT NULL
        AND action_code in ('ISSUE', 'TRANSFER', 'SACC')
    );

-- +goose Down
DROP VIEW IF EXISTS transport_document_state CASCADE;
DROP VIEW IF EXISTS transport_document_possession CASCADE;
