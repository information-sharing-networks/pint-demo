This directory contains test transport document (ebl) files created based on DCSA openapi v3.0.2 sample data

Note that the following fields in `HHL71800000.json` were manually computed and are used to test the manifest generation code:
- eBLVisualisationByCarrier
- issuanceManifestSignedContent

if you need to recreate these fields, follow the instructions below.

# eBLVisualisationByCarrier
`eBLVisualisationByCarrier` is an optional field in the DCSA Issuance Request that allows the carrier to provide a human-readable visualization of the eBl.

For the sample test record, there is a manually created pdf file `HHL71800000.pdf`.  
`eblVisualisationByCarrier.content` is base64 encoded string of the binary content of the associated visualisation file.


If you change this file you must also update the `eBLVisualisationByCarrier.content` field with the base64 encoded version of the updated binary content. If you change the file name or mime type, you also need to update `eblVisualisationByCarrier.name` and `eblVisualisationByCarrier.contentType` respectively.


# issuanceManifestSignedContent 
this field is used by receiving parties to verify the 3 parts of the transport docuement (document details, issueTo, and eBLVisualisationByCarrier) have not been tampered with since issuance.

This field is created in two steps - firstly create the intermediary `IssuanceManifest.json` file, and then sign that file with the private key of the carrier 

## IssuanceManifest.json
this file is created by:

1. taking the value of `document` from `testdata/transport-documents/HHL71800000.json`
2. Canonicalizing the json from step 1 
3. SHA256 the canonicalized json from step 2
4. taking the value of `issueTo` from `testdata/transport-documents/HHL71800000.json`
5. Canonicalizing the json from step 4  
6. SHA256 the canonicalized json from step 5
2. base64 decode the value of `eBLVisualisationByCarrier.content` from `testdata/transport-documents/HHL71800000.json`
7. SHA256 the decoded binary content from step 6

The output from steps 3, 6, and 8 are the values for the `documentChecksum`, `issueToChecksum`, and `eBLVisualisationByCarrierChecksum` fields in the `IssuanceManifest.json` file.

## Sign the IssuanceManifest.json
1. Calculate the key-id by calculating the JWK thumbprint of the public key of the carrier.  
2. Canonicalize the `IssuanceManifest.json`
3. Sign the canonicalized json with the private key of the carrier (testdata/keys/ed25519-carrier.example.com.private.jwk)
4. Encode the signed content in JWS compact serialization format
5. update the `issuanceManifestSignedContent` field in `testdata/transport-documents/HHL71800000.json` with the value from step 3

There are three sample json records in this directory:
- `HHL71800000-unsigned.json` - this is the complete issuance request payload with an unsigned `issuanceManifestSignedContent` field
- `HHL71800000-ed25519.json` - this is the complete issuance request payload that was signed with sample-carrier-ed25519.example.com private key  - the signature is ED25519
- `HHL71800000-rsa.json` - this is the complete issuance request payload that was signed with sample-carrier-rsa.example.com private key  - the signature is RSA256

the JWS signatures include the corresponding certs for the carrier in the x5c header.