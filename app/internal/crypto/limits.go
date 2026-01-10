package crypto

// MaxDocumentSize is the default maximum allowed size for documents (JSON and base64-encoded content).
// This limit applies to:
// - JSON documents (transport documents, issueTo, etc.) before canonicalization
// - Base64-encoded content (eBLVisualisationByCarrier, additional documents) before decoding
//
//	TODO allow to be overriden by an server config environment variable (MAX_DOCUMENT_SIZE).
var MaxDocumentSize int64 = 10 * 1024 * 1024 // 10MB
