# running the DCSA conformance (CTK) tests
Follow the instructions in the CTK repo (https://github.com/dcsaorg/Conformance-Gateway) to start the webui and navigate to the `pint-300-conformance-manual-receivingplatform-testing` 

Use the settings icon in the webui to set the `Application base URL` to http://host.docker.internal:8081 (note the main conformance app uses 8080)

to start the pint-server for conformance testing:
```bash
# the PINT conformance tests will send PINT transfers to this server (configured as CARX in the registry)
# The sending platform is configured as BOLE and the carrier is configured as CARR 
 X5C_CERT_PATH="" X5C_CUSTOM_ROOTS_PATH="" SIGNING_KEY_PATH=test/testdata/keys/ctk-carx.example.com.private.jwk MIN_TRUST_LEVEL=1 PLATFORM_CODE=CARX PORT=8081 make docker-up
 ```

When running manual tests, the CTK webui requires the public key used by the receiving pint-server to be pasted in for each test (it needs this to verify the JWS signature in the response)

Note the webui is fussy about the format (wants it to be a PEM cert file on a single line)

The CARX cert is - this can be copied directly to the webui.
```pem
-----BEGIN CERTIFICATE-----\nMIIDFzCCAf+gAwIBAgIUAgw3n2K3vkGH5Y134HriPB6zVycwDQYJKoZIhvcNAQEL\nBQAwGzEZMBcGA1UEAwwQVGVzdCBDZXJ0aWZpY2F0ZTAeFw0yNjAyMTYxMDQxMDda\nFw0yNzAyMTYxMDQxMDdaMBsxGTAXBgNVBAMMEFRlc3QgQ2VydGlmaWNhdGUwggEi\nMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCaIhxWgk+mxDVtTc9moiFM0QNn\nzpAH5HdMcWr8bz4CSlWaC42not7d1JlAVz282vd6liA4bLn0eDdqPPZ7KDiq6bWD\nho3SOCBWjiQNovPty5j6qhTkrgKc1x52sTYqnYMkfop33kpUgcflGg+FxkJzxbCu\nwqS6CKHj9DjCEIWonlEiq50ffijErxDilhICyM+erOAypjFDcq0yHOHOd5GH1S4p\nRdozKh30BwGfFxnNrbAuijEh/2v/eWVmqpP/GUrXS/Jb9WfKY014bVCS13AnoKeq\n+RY0z2XASPZF8Ix5e89RPcH9DzqGrsrjRBp5apNfDA+gX3/J8OCitI9uXcZfAgMB\nAAGjUzBRMB0GA1UdDgQWBBRwejV7MgzEfwsZh+UIZtNHo8oFPDAfBgNVHSMEGDAW\ngBRwejV7MgzEfwsZh+UIZtNHo8oFPDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\nDQEBCwUAA4IBAQBCyL6zZCM+Nl8lT//Odzhs83blCI2z5vtNevfEm0OSy62dpMsy\nNwaYz/imRvF+ehLKQM42WbPDijTD865T4rzpsoKZz0hDURkqDZFNEyFDzVDhPXtD\nrXoZVHM0sRA5yW9vNDjqDgPBioQd+Rdj3rG7YmKR7OUaTK0ApFBtDAO9JTCK7qLk\nAOBCbq6ER8QXOpehhhQpoEsMpbIJp3HPX8FMCGE6yHvp4VQOkb/T7eqWa/GozIBM\nzuimZN6HDrZCKTsz31PjhAJDjiLPrnUrMitlMkKUVbVexeaXfCsJXo/u9+DBG7En\nL4hV5QaDfS2NWel1CBdfm1rEnvtZ49/t530p\n-----END CERTIFICATE-----\n
```
This was generated as follows
```bash
openssl req -new -x509 -key ctk-carx.example.com.private.pem -out certificate.pem -days 365 -subj "/CN=Test Certificate" && \
awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' certificate.pem
```

# limitations
- if you are starting with a fresh database, you will need to create the party data CTK tests expect (see instructions below)

- the pint demo tests will submit different transfer chain entries for the same ebl, but the pint-server will detect these as DISE errors and reject them.
Consequenly you will need to delete the envelopes between tests:

```bash
make delete-envelopes` # will delete all envelopes from the database.
```

# create the parties needed by CTK
the tests expect some party data to be loaded. Use the curl commands below to create them.

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

# Keys used in the conformance tests

The carrier and sender private keys used by the CTK when signing PINT transfers are found in:
`Conformance-Gateway/ebl/src/main/java/org/dcsa/conformance/standards/ebl/crypto/PayloadSignerFactory.java`

c.f CTK_SENDER_PRIVATE_KEY_PEM and CTK_CARRIER_PRIVATE_RSA_KEY_PEM

the keys have been converted to JWKs and added to the `../testdata/keys/` directory as:
- `ctk-bole.example.com.private.jwk`
- `ctk-carr.example.com.private.jwk`

the kids have to be added to the `platform-registry/eblsolutionproviders.csv` file.

The private key used by the pint-server when signing responses to the CTK tests is `ctk-carx.example.com` and was created with:
```bash
go run /mydir/pint-demo/app/cmd/keygen/main.go -d ctk-carx.example.com -o . -t rsa  -s 2048
```

