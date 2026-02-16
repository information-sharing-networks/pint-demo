

# running the DCSA conformance (CTK) tests
(see https://github.com/dcsaorg/Conformance-Gateway).

The carrier and sender private keys used by the CTK when signing PINT transfers are found in:
`Conformance-Gateway/ebl/src/main/java/org/dcsa/conformance/standards/ebl/crypto/PayloadSignerFactory.java`
c.f CTK_SENDER_PRIVATE_KEY_PEM  CTK_CARRIER_PRIVATE_RSA_KEY_PEM

These have been copied to the current directory as:
- `sender-private.pem`
- `carrier-private.pem`


The go command below is used to create the jwks needed by the pint-server to verify the CTK test transfer requests:
```bash
go run main.go -o . -p sender-private.pem -s sender-ctk.example.com 
go run main.go -o . -p carrier-private.pem -s carrier-ctk.example.com 
```

these keys have beeen copied to testdata/keys.

the kids have to be added to the `platform-registry/eblsolutionproviders.csv` file:
- carrier (cd4353893e5552ec) 
- sender (62672234fc926888)

... the current registry csv file has them as CARR and BOLE respectively.

The private key used to start the pint-server for conformance testing is CARX/`conformance-eblplatform.example.com` and was created with:
```bash
# note use a RSA signing key as ed25519 doesn't work with the conformance platform for some reason
go run /mydir/pint-demo/app/cmd/keygen/main.go -d conformance-eblplatform.example.com -o . -t rsa  -s 2048
cp conformance-eblplatform.example.com.*.jwk ../testdata/keys/
```

the registry was udated with the kid from tmp/conformance-eblplatform.example.com.public.jwk
`../testdata/platform-registry/eblsolutionproviders.csv`:

"CARX,https://conformance-eblplatform.example.com/,,d554a38fd3bbe54f"

the conformance test server requires the public key to be copied in for each test when running manually. 
The key needs to be a PEM cert file on a single line and can be created by:
```bash
openssl req -new -x509 -key conformance-eblplatform.example.com.private.pem -out certificate.pem -days 365 -subj "/CN=Test Certificate" && \
awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' certificate.pem
```

the current cert is :
```pem
-----BEGIN CERTIFICATE-----\nMIIDFzCCAf+gAwIBAgIUAgw3n2K3vkGH5Y134HriPB6zVycwDQYJKoZIhvcNAQEL\nBQAwGzEZMBcGA1UEAwwQVGVzdCBDZXJ0aWZpY2F0ZTAeFw0yNjAyMTYxMDQxMDda\nFw0yNzAyMTYxMDQxMDdaMBsxGTAXBgNVBAMMEFRlc3QgQ2VydGlmaWNhdGUwggEi\nMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCaIhxWgk+mxDVtTc9moiFM0QNn\nzpAH5HdMcWr8bz4CSlWaC42not7d1JlAVz282vd6liA4bLn0eDdqPPZ7KDiq6bWD\nho3SOCBWjiQNovPty5j6qhTkrgKc1x52sTYqnYMkfop33kpUgcflGg+FxkJzxbCu\nwqS6CKHj9DjCEIWonlEiq50ffijErxDilhICyM+erOAypjFDcq0yHOHOd5GH1S4p\nRdozKh30BwGfFxnNrbAuijEh/2v/eWVmqpP/GUrXS/Jb9WfKY014bVCS13AnoKeq\n+RY0z2XASPZF8Ix5e89RPcH9DzqGrsrjRBp5apNfDA+gX3/J8OCitI9uXcZfAgMB\nAAGjUzBRMB0GA1UdDgQWBBRwejV7MgzEfwsZh+UIZtNHo8oFPDAfBgNVHSMEGDAW\ngBRwejV7MgzEfwsZh+UIZtNHo8oFPDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\nDQEBCwUAA4IBAQBCyL6zZCM+Nl8lT//Odzhs83blCI2z5vtNevfEm0OSy62dpMsy\nNwaYz/imRvF+ehLKQM42WbPDijTD865T4rzpsoKZz0hDURkqDZFNEyFDzVDhPXtD\nrXoZVHM0sRA5yW9vNDjqDgPBioQd+Rdj3rG7YmKR7OUaTK0ApFBtDAO9JTCK7qLk\nAOBCbq6ER8QXOpehhhQpoEsMpbIJp3HPX8FMCGE6yHvp4VQOkb/T7eqWa/GozIBM\nzuimZN6HDrZCKTsz31PjhAJDjiLPrnUrMitlMkKUVbVexeaXfCsJXo/u9+DBG7En\nL4hV5QaDfS2NWel1CBdfm1rEnvtZ49/t530p\n-----END CERTIFICATE-----\n
```

Alternatively, although the receiver key is not currently configurable in the CTK, you can replace the default receiver private key in to avoid copying the public key in manually before each test.
`Conformance-Gateway/ebl/src/main/java/org/dcsa/conformance/standards/ebl/crypto/PayloadSignerFactory.java`
(c.f CTK_RECEIVER_PRIVATE_KEY_PEM)

# running the conformance tests
follow the instructions in the CTK repo to start the webui and navigate to the `pint-300-conformance-manual-receivingplatform-testing-` 

you need to using the settings icon to set the `Application base URL` to http://host.docker.internal:8081 (note the main conformance app uses 8080)


to start the pint-server for conformance testing:
```bash
 X5C_CERT_PATH="" X5C_CUSTOM_ROOTS_PATH="" SIGNING_KEY_PATH=test/testdata/keys/conformance-eblplatform.example.com.private.jwk MIN_TRUST_LEVEL=1 PLATFORM_CODE=CARX PORT=8081 make docker-up
 ```
the tests expect some party data to be loaded (see the curl commands below)

-- parties
```bash
curl -s -X POST "http://localhost:8081/admin/parties" \
 -H 'accept: application/json'\
 -H 'content-type: application/json' \
 -d '{"active":true,"partyName":"Jane Doe"}'  |jq

id=$(curl -s -X GET "http://localhost:8081/admin/parties/Jane%20Doe" -H 'accept: application/json' | jq -r '.id')

curl -s -X POST http://localhost:8081/admin/parties/$id/codes \
 -H 'accept: application/json'\
 -H 'content-type: application/json' \
 -d '{"codeListProvider":"CARX","partyCode":"12345-jane-doe"}'  | jq


curl -s -X POST http://localhost:8081/admin/parties/$id/codes \
 -H 'accept: application/json'\
 -H 'content-type: application/json' \
 -d '{"codeListProvider":"ZZZ","partyCode":"valid-party", "codeListName":"CTK"}'  | jq
```
