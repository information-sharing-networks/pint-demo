package ebl

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

// sanity check to confirm we can correctly recreate the manually computed signatures and
// checksums in HHL71800000-ed25519.json and HHL71800000-rsa.json
func TestRecreateSampleIssuanceManifestEd25519(t *testing.T) {

	sampleRecordPath := "../../test/testdata/issuance-documents/HHL71800000-ed25519.json"
	privateKeyPath := "../../test/testdata/keys/ed25519-carrier.example.com.private.jwk"
	certPath := "../../test/testdata/certs/ed25519-carrier.example.com-fullchain.crt"
	eBLVisualisationPath := "../../test/testdata/issuance-documents/HHL71800000.pdf"

	data, err := os.ReadFile(sampleRecordPath)
	if err != nil {
		t.Fatalf("could not open %s: %v", sampleRecordPath, err)
	}

	// unmarshal the sample issuance request - we will use the document and issueTo JSON as the basis for our new record
	// the other fields are recreated and compared to ensure we got the same result.
	var sampleIssuanceRequest struct {
		Document                      json.RawMessage            `json:"document"`
		IssueTo                       json.RawMessage            `json:"issueTo"`
		EBLVisualisationByCarrier     *EBLVisualisationByCarrier `json:"eBLVisualisationByCarrier"`
		IssuanceManifestSignedContent string                     `json:"issuanceManifestSignedContent"`
	}

	err = json.Unmarshal(data, &sampleIssuanceRequest)
	if err != nil {
		t.Fatalf("could not marshal bl json: %v", err)
	}

	// use the JSON data from the sample and the precreated pdf as input to create a new issuance request
	newIssuanceRequestInput := IssuanceRequestInput{
		Document:                 sampleIssuanceRequest.Document,
		IssueTo:                  sampleIssuanceRequest.IssueTo,
		EBLVisualisationFilePath: eBLVisualisationPath,
	}

	// Load the private key and certificate chain
	privateKey, err := crypto.ReadPrivateKeyFromJWKFile(privateKeyPath)
	if err != nil {
		t.Fatalf("failed to load private key: %v", err)
	}

	certChain, err := crypto.ReadCertChainFromPEMFile(certPath)
	if err != nil {
		t.Fatalf("failed to load certificate chain: %v", err)
	}

	newIssuanceRequest, err := CreateIssuanceRequest(
		newIssuanceRequestInput,
		privateKey,
		certChain,
	)

	if err != nil {
		t.Fatalf("could not create issuance request: %v", err)
	}
	if newIssuanceRequest == nil {
		t.Fatalf("issuance request is nil")
	}

	signature := newIssuanceRequest.IssuanceManifestSignedContent
	if string(signature) == "" {
		t.Fatalf("signature is empty")
	}

	//t.Logf("signature: %v", signature)
	if string(signature) != sampleIssuanceRequest.IssuanceManifestSignedContent {
		t.Errorf("signature does not match sample")
	}

	// check the eblVisualisationByCarrier is correct
	if newIssuanceRequest.EBLVisualisationByCarrier == nil {
		t.Fatalf("eBLVisualisationByCarrier is nil")
	}
	if newIssuanceRequest.EBLVisualisationByCarrier.Name != sampleIssuanceRequest.EBLVisualisationByCarrier.Name {
		t.Errorf("eBLVisualisationByCarrier.Name does not match sample")
	}
	if newIssuanceRequest.EBLVisualisationByCarrier.ContentType != sampleIssuanceRequest.EBLVisualisationByCarrier.ContentType {
		t.Errorf("eBLVisualisationByCarrier.ContentType does not match sample")
	}
	if newIssuanceRequest.EBLVisualisationByCarrier.Content != sampleIssuanceRequest.EBLVisualisationByCarrier.Content {
		t.Errorf("eBLVisualisationByCarrier.Content does not match sample")
	}

}
func TestRecreateSampleIssuanceManifestRSA(t *testing.T) {

	sampleRecordPath := "../../test/testdata/issuance-documents/HHL71800000-rsa.json"
	privateKeyPath := "../../test/testdata/keys/rsa-carrier.example.com.private.jwk"
	certPath := "../../test/testdata/certs/rsa-carrier.example.com-fullchain.crt"
	VisualisationPath := "../../test/testdata/issuance-documents/HHL71800000.pdf"

	// Load the private key and certificate chain
	privateKey, err := crypto.ReadPrivateKeyFromJWKFile(privateKeyPath)
	if err != nil {
		t.Fatalf("failed to load private key: %v", err)
	}

	certChain, err := crypto.ReadCertChainFromPEMFile(certPath)
	if err != nil {
		t.Fatalf("failed to load certificate chain: %v", err)
	}
	data, err := os.ReadFile(sampleRecordPath)
	if err != nil {
		t.Fatalf("could not open %s: %v", sampleRecordPath, err)
	}

	var sampleIssuanceRequest struct {
		Document                      json.RawMessage            `json:"document"`
		IssueTo                       json.RawMessage            `json:"issueTo"`
		EBLVisualisationByCarrier     *EBLVisualisationByCarrier `json:"eBLVisualisationByCarrier"`
		IssuanceManifestSignedContent string                     `json:"issuanceManifestSignedContent"`
	}

	err = json.Unmarshal(data, &sampleIssuanceRequest)
	if err != nil {
		t.Fatalf("could not marshal bl json: %v", err)
	}

	// use the JSON data from the sample and the precreated pdf as input to create a new issuance request
	newIssuanceRequestInput := IssuanceRequestInput{
		Document:                 sampleIssuanceRequest.Document,
		IssueTo:                  sampleIssuanceRequest.IssueTo,
		EBLVisualisationFilePath: VisualisationPath,
	}

	newIssuanceRequest, err := CreateIssuanceRequest(
		newIssuanceRequestInput,
		privateKey,
		certChain,
	)

	if err != nil {
		t.Fatalf("could not create issuance request: %v", err)
	}
	if newIssuanceRequest == nil {
		t.Fatalf("issuance request is nil")
	}

	// check the signature is correct
	signature := newIssuanceRequest.IssuanceManifestSignedContent
	if string(signature) == "" {
		t.Fatalf("signature is empty")
	}

	//t.Logf("signature: %v", signature)
	if string(signature) != sampleIssuanceRequest.IssuanceManifestSignedContent {
		t.Errorf("signature does not match sample")
	}

	// check the eblVisualisationByCarrier is correct
	if newIssuanceRequest.EBLVisualisationByCarrier == nil {
		t.Fatalf("eBLVisualisationByCarrier is nil")
	}
	if newIssuanceRequest.EBLVisualisationByCarrier.Name != sampleIssuanceRequest.EBLVisualisationByCarrier.Name {
		t.Errorf("eBLVisualisationByCarrier.Name does not match sample")
	}
	if newIssuanceRequest.EBLVisualisationByCarrier.ContentType != sampleIssuanceRequest.EBLVisualisationByCarrier.ContentType {
		t.Errorf("eBLVisualisationByCarrier.ContentType does not match sample")
	}
	if newIssuanceRequest.EBLVisualisationByCarrier.Content != sampleIssuanceRequest.EBLVisualisationByCarrier.Content {
		t.Errorf("eBLVisualisationByCarrier.Content does not match sample")
	}

}
