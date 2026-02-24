-- +goose Up    

-- transport_document_latest - view showing the latest event for each eBL document
CREATE VIEW transport_document_state AS
    SELECT id envelope_id, transport_document_checksum, action_code, sent_by_platform_code, received_by_platform_code, created_at, accepted_at IS NOT NULL AS accepted, accepted_at FROM envelopes
    WHERE id IN (
        SELECT id FROM envelopes e
        WHERE created_at = (
            SELECT MAX(created_at)
            FROM envelopes 
            WHERE transport_document_checksum = e.transport_document_checksum
        )
    );

CREATE VIEW transport_document_history AS
    SELECT id envelope_id, transport_document_checksum, action_code, sent_by_platform_code, received_by_platform_code, created_at, accepted_at IS NOT NULL AS accepted, accepted_at FROM envelopes
    ORDER BY created_at DESC;

-- +goose Down
DROP VIEW IF EXISTS transport_document_state CASCADE;
DROP VIEW IF EXISTS transport_document_history CASCADE;
