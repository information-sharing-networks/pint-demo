-- +goose Up    

-- transport_document_events - Log of all events related to a specific eBL document (identified by checksum)
CREATE TABLE transport_document_events (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    transport_document_checksum TEXT NOT NULL,
    envelope_id UUID NOT NULL, -- Reference to the envelope that caused the event
    action_code TEXT NOT NULL CHECK (action_code IN ('ISSUE', 'TRANSFER', 'ENDORSE', 'ENDORSE_TO_ORDER', 'BLANK_ENDORSE', 'SIGN', 'SURRENDER_FOR_AMENDMENT', 'SURRENDER_FOR_DELIVERY', 'SACC', 'SREJ')),
    platform_code TEXT NOT NULL, -- DCSA platform code of the platform that received the event
    accepted BOOLEAN NOT NULL DEFAULT FALSE, -- True if the event was accepted, false if it was rejected

    CONSTRAINT fk_transport_document_events_transport_document FOREIGN KEY (transport_document_checksum)
        REFERENCES transport_documents(checksum)
        ON DELETE CASCADE,
    CONSTRAINT fk_transport_document_events_envelope FOREIGN KEY (envelope_id)
        REFERENCES envelopes(id)
        ON DELETE CASCADE
);
CREATE INDEX idx_transport_document_events_transport_document ON transport_document_events(transport_document_checksum);

-- transport_document_latest - view showing the latest event for each eBL document
CREATE VIEW transport_document_latest AS
    SELECT * FROM transport_document_events
    WHERE id IN (
        SELECT id FROM transport_document_events e
        WHERE created_at = (
            SELECT MAX(created_at)
            FROM transport_document_events
            WHERE transport_document_checksum = e.transport_document_checksum
        )
    );

-- transport_document_latest_accepted - view showing the latest accepted event for each eBL document
CREATE VIEW transport_document_latest_accepted AS
    SELECT * FROM transport_document_events
    WHERE id IN (
        SELECT id FROM transport_document_events e
        WHERE accepted = true
          AND created_at = (
            SELECT MAX(created_at)
            FROM transport_document_events
            WHERE transport_document_checksum = e.transport_document_checksum
        )
    );
-- +goose Down
DROP TABLE IF EXISTS transport_document_events CASCADE;
