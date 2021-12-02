package tlsigning

import (
	"fmt"

	"github.com/Truelayer/truelayer-signing/go/errors"
	"github.com/Truelayer/truelayer-signing/go/jws"
	"github.com/Truelayer/truelayer-signing/go/sign"
	"github.com/Truelayer/truelayer-signing/go/verify"
)

// SignWithPem starts building a request "Tl-Signature" header value using private key
// pem data & the key's "kid".
func SignWithPem(kid string, privatekeyPem []byte) *sign.Signer {
	return sign.NewSigner(kid, privatekeyPem)
}

// VerifyWithPem starts building a "Tl-Signature" header verifier using public key pem data.
func VerifyWithPem(publicKeyPem []byte) *verify.Verifier {
	return verify.NewVerifier(publicKeyPem)
}

// VerifyWithJwks start building a `Tl-Signature` header verifier using public key JWKs JSON response data.
func VerifyWithJwks(jwks []byte) *verify.Verifier {
	return verify.NewVerifierWithJwks(jwks)
}

// ExtractJwsHeader extracts "JwsHeader" info from a "Tl-Signature" header value.
//
// This can then be used to pick a verification key using the "kid" etc.
func ExtractJwsHeader(tlSignature string) (*jws.JwsHeader, error) {
	tlSignatureData, err := verify.ParseTlSignature(tlSignature)
	if err != nil {
		return nil, errors.NewJwsError(fmt.Sprintf("signature parsing failed: %v", err))
	}
	return tlSignatureData.JwsHeader, nil
}
