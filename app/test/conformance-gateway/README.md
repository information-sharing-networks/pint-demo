
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

