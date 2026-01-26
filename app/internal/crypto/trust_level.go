package crypto

// trust.go - Trust level definitions and certificate validation logic
//
// Trust levels are determined by analyzing the x5c (X.509 certificate chain) in JWS headers.
// The trust level indicates the strength of identity verification for a signature:
//
// - TrustLevelEVOV: Organization identity verified by CA (EV/OV certificates)
// - TrustLevelDV: Domain ownership verified by CA (DV certificates)
// - TrustLevelNoX5C: No certificate chain present (testing only)
//
// trust level is used by the pint-demo service at startup to determine which trust level to require for signatures.
// the trust level is established when verifying the JWS signatures in the ebl envelope.

import (
	"fmt"
)

// TrustLevel represents the trust level of a signature and is determined by the x5c (X.509 certificate chain) in the JWS header.
//
// this implementation uses x5c headers to support the DCSA non-repudiation requirements.
type TrustLevel int

const (
	// TrustLevelEVOV represents signatures with x5c certs that use Extended Validation (EV) or Organization Validation (OV) certificates.
	//	- Organisation identity verified by CA (provides non-repudiation)
	//	- Recommended for production digital signatures
	TrustLevelEVOV TrustLevel = 1

	// TrustLevelDV - certs with Domain Validation (DV) certificates.
	//	- Domain ownership verified by CA
	// 	- May be acceptable for production depending on policy
	TrustLevelDV TrustLevel = 2

	// TrustLevelNoX5C represents keys without any certificate chain
	//	- The signature has no identity proof
	//	- recommended for testing only
	TrustLevelNoX5C TrustLevel = 3
)

// String returns a human-readable string representation of the trust level.
func (t TrustLevel) String() string {
	switch t {
	case TrustLevelEVOV:
		return "EV/OV (Organization Validated)"
	case TrustLevelDV:
		return "DV (Domain Validated)"
	case TrustLevelNoX5C:
		return "No X5C (Testing Only)"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

// DetermineTrustLevel analyzes a JWS signature to determine its trust level based on the x5c certificate chain.
//
// Background: The sending platform can optionally include a certificate chain in the JWS header.
// The leaf certificate in the chain must be signed by an approved CA in order
// to prove the identity of the org running the platform.
//
// Note: you should call VerifyJWS() first to verify the signature and certificate chain
// before using this function.
//
// The certificate type is used to determine the trust level as follows:
//
//	TrustLevelEVOV: Certificates containing a Subject.Organization field
//
// ... are considered to be either Organization Validation (OV) or Extended Validation (EV) certificates.
// This means they were issued to a specific organization that has been
// verified by a Certificate Authority.
// This level is recommended for production use.
//
//	TrustLevelDV: Certificates without an Organization field
//
// ... are considered to be Domain Validation (DV) certificates
// this trust level may be allowed in production, depending on policy.
//
//	TrustLevelNoX5C: no x5c header present in the JWS
//
// This means the signature has no identity proof - recommended for testing only.
//
// Parameters:
//   - jwsString: JWS compact serialization (header.payload.signature)
//
// Returns the trust level based on the certificate type in the x5c header.
func DetermineTrustLevel(jwsString string) (TrustLevel, error) {
	// Extract x5c from JWS (optional)
	certChain, err := ParseX5CFromJWS(jwsString)
	if err != nil {
		return TrustLevelNoX5C, WrapCertificateError(err, "failed to parse x5c")
	}

	// nil certChain means no x5c header was present
	if certChain == nil {
		return TrustLevelNoX5C, nil
	}

	// get the leaf certificate (platform certificate)
	cert := certChain[0]
	if cert == nil {
		return TrustLevelNoX5C, NewInternalError("leaf certificate is nil")
	}

	// TODO - do we need more robust EV/OV detection?
	// Check if the certificate has an Organization field in the Subject
	// OV and EV certificates require this field; DV certificates typically don't have it
	if len(cert.Subject.Organization) > 0 && cert.Subject.Organization[0] != "" {
		return TrustLevelEVOV, nil
	}

	return TrustLevelDV, nil
}
