package crypto

import (
	"encoding/json"
	"os"
	"testing"
)

// sanity check to confirm we can correctly recreate the manually computed signatures in
// HHL71800000-ed25519.json and HHL71800000-rsa.json
func TestRecreateSampleIssuanceManifestEd25519(t *testing.T) {

	sampleRecordPath := "testdata/transport-documents/HHL71800000-ed25519.json"
	privateKeyPath := "testdata/keys/ed25519-carrier.example.com.private.jwk"
	certPath := "testdata/certs/ed25519-carrier.example.com-fullchain.crt"
	visualizationPath := "testdata/transport-documents/HHL71800000.pdf"

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

	// use the sample business data and precreated pdf as input to create a new issuance request
	newIssuanceRequestInput := IssuanceRequestInput{
		Document:                 sampleIssuanceRequest.Document,
		IssueTo:                  sampleIssuanceRequest.IssueTo,
		EBLVisualizationFilePath: visualizationPath, //TODO z to s to confirm with uk eng used in spec
	}

	newIssuanceRequest, err := CreateIssuanceRequest(
		newIssuanceRequestInput,
		AlgorithmEd25519,
		privateKeyPath,
		certPath,
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

	sampleRecordPath := "testdata/transport-documents/HHL71800000-rsa.json"
	privateKeyPath := "testdata/keys/rsa-carrier.example.com.private.jwk"
	certPath := "testdata/certs/rsa-carrier.example.com-fullchain.crt"
	visualizationPath := "testdata/transport-documents/HHL71800000.pdf"

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

	// use the sample business data and precreated pdf as input to create a new issuance request
	newIssuanceRequestInput := IssuanceRequestInput{
		Document:                 sampleIssuanceRequest.Document,
		IssueTo:                  sampleIssuanceRequest.IssueTo,
		EBLVisualizationFilePath: visualizationPath, //TODO z to s to confirm with uk eng used in spec
	}

	newIssuanceRequest, err := CreateIssuanceRequest(
		newIssuanceRequestInput,
		AlgorithmRSA,
		privateKeyPath,
		certPath,
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
