
the go code in this directory is used to create public jwks from private key PEM files for 
running the DCSA conformance (CTK) testss.

The carrier and sender private keys used by the CTK when signing PINT transfers are found in:
`Conformance-Gateway/ebl/src/main/java/org/dcsa/conformance/standards/ebl/crypto/PayloadSignerFactory.java`
c.f CTK_SENDER_PRIVATE_KEY_PEM  CTK_CARRIER_PRIVATE_RSA_KEY_PEM

The go command is used to create the jwks for the CTK sender and carrier
```bash
go run main.go -o . -p sender-private.pem -s sender-ctk.example.com 
go run main.go -o . -p carrier-private.pem -s carrier-ctk.example.com 
```

these keys can be copied to testdata/keys 

the kids also need to be added to the `platform-registry/eblsolutionproviders.csv` file:
carrier (cd4353893e5552ec) 
sender (62672234fc926888)

... they are added to the testdata registry csv file as CARR and BOLE respectively.


X5C_CERT_PATH=test/testdata/certs/rsa-eblplatform.example.com-fullchain.crt SIGNING_KEY_PATH=test/testdata/keys/rsa-eblplatform.example.com.private.jwk MIN_TRUST_LEVEL=1 PLATFORM_CODE=CARX PORT=8081 make docker-up

 X5C_CERT_PATH="" X5C_CUSTOM_ROOTS_PATH="" SIGNING_KEY_PATH=test/testdata/keys/rsa-eblplatform.example.com.private.jwk MIN_TRUST_LEVEL=1 PLATFORM_CODE=CARX PORT=8081 make docker-up


cert for test harness
"-----BEGIN CERTIFICATE-----\nMIIC+jCCAqygAwIBAgIUD7UzLf6eZSRPeH8/vmHvMwV0vfowBQYDK2VwMG4xCzAJBgNVBAYTAkdCMRAwDgYDVQQIDAdFbmdsYW5kMQ8wDQYDVQQHDAZMb25kb24xHTAbBgNVBAoMFFRlc3QgSW50ZXJtZWRpYXRlIENBMR0wGwYDVQQDDBRUZXN0IEludGVybWVkaWF0ZSBDQTAeFw0yNjAxMTUxMDMxMjNaFw0zNjAxMTMxMDMxMjNaMHAxCzAJBgNVBAYTAkdCMRAwDgYDVQQIDAdFbmdsYW5kMQ8wDQYDVQQHDAZMb25kb24xGDAWBgNVBAoMD3JzYS1lYmxwbGF0Zm9ybTEkMCIGA1UEAwwbcnNhLWVibHBsYXRmb3JtLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4Jc3bVfxFPoYunqlIF7KqpTNXELrvnpKIllVPTGPrQpejEB/IYFnVkd1xp+2RpKX6jw7/SEUS3n4p1qj0NKlgjwfzyhD0u821Hrxd4SAunQTkIKNlYHxfCvApsVWTK6Q3wpnfSdDXiqyGJ01Qdk+hW5oxsfTkCZY/a35KGzE0u+x96EH2etLx+K3DwMWgoFnkZPZb9aqL2q/ERkssmhZNeI1ckXLR8eYFGqg8+EQh+2WtN0iOeeSS9KO1v3/Csv0XOhfd7B1UQFqr8T8UxnQrI+7qNyS1s70qsLgA8hMStU59SNPU4XDjvI4HqmFKudyBP0NaL/COMbzuGRvlap9kwIDAQABo2AwXjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUkHIAUdtIjiULl9pgY09r7kpMzKswHwYDVR0jBBgwFoAU5YY664uLWJHSZxparExcGf9hE1gwBQYDK2VwA0EAYtBYF6Vjb00d1OWV8TrGUkjYFgymO6z9QBqJb32J/9uHWOK6bNTOttVODAsedVI8w+MnvsLNArSL94ZOC3+iDA==\n-----END CERTIFICATE-----\n"

-- note the test harness creates transfer chains with new dates each time, so these will look like new transfers

-- parties
curl -X POST "http://localhost:8081/admin/parties" \
 -H 'accept: application/json'\
 -H 'content-type: application/json' \
 -d '{"active":true,"partyName":"Jane Doe"}' 

 todo jq
 curl -X POST "http://localhost:8081/admin/parties/e00c4002-302f-404d-8077-74e847ceb674/codes" \
 -H 'accept: application/json'\
 -H 'content-type: application/json' \
 -d '{"codeListProvider":"CARX","partyCode":"12345-jane-doe"}' 